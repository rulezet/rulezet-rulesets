rule TTP_XOR_WriteProcessMemory_6c2a {
  strings:
    $key_6c2a = { 3b 58 [2] 09 7a [2] 0f 4f [2] 21 4f [2] 1e 53 }

  condition:
    any of them
}