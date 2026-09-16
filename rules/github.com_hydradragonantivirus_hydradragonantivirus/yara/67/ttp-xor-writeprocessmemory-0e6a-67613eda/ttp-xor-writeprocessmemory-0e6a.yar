rule TTP_XOR_WriteProcessMemory_0e6a {
  strings:
    $key_0e6a = { 59 18 [2] 6b 3a [2] 6d 0f [2] 43 0f [2] 7c 13 }

  condition:
    any of them
}