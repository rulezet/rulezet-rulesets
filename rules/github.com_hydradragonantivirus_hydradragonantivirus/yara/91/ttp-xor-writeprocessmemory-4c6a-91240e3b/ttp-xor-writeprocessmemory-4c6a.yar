rule TTP_XOR_WriteProcessMemory_4c6a {
  strings:
    $key_4c6a = { 1b 18 [2] 29 3a [2] 2f 0f [2] 01 0f [2] 3e 13 }

  condition:
    any of them
}