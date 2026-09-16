rule TTP_XOR_WriteProcessMemory_6c1a {
  strings:
    $key_6c1a = { 3b 68 [2] 09 4a [2] 0f 7f [2] 21 7f [2] 1e 63 }

  condition:
    any of them
}