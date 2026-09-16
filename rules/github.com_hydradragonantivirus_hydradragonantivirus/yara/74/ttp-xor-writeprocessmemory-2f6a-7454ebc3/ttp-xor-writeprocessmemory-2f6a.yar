rule TTP_XOR_WriteProcessMemory_2f6a {
  strings:
    $key_2f6a = { 78 18 [2] 4a 3a [2] 4c 0f [2] 62 0f [2] 5d 13 }

  condition:
    any of them
}