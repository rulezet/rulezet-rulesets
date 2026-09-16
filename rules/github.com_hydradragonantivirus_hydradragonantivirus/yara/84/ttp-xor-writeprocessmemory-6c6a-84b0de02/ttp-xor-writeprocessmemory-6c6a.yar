rule TTP_XOR_WriteProcessMemory_6c6a {
  strings:
    $key_6c6a = { 3b 18 [2] 09 3a [2] 0f 0f [2] 21 0f [2] 1e 13 }

  condition:
    any of them
}