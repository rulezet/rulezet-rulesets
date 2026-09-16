rule TTP_XOR_WriteProcessMemory_2f3a {
  strings:
    $key_2f3a = { 78 48 [2] 4a 6a [2] 4c 5f [2] 62 5f [2] 5d 43 }

  condition:
    any of them
}