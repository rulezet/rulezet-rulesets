rule TTP_XOR_WriteProcessMemory_4a6a {
  strings:
    $key_4a6a = { 1d 18 [2] 2f 3a [2] 29 0f [2] 07 0f [2] 38 13 }

  condition:
    any of them
}