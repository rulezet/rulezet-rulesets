rule TTP_XOR_WriteProcessMemory_2f5a {
  strings:
    $key_2f5a = { 78 28 [2] 4a 0a [2] 4c 3f [2] 62 3f [2] 5d 23 }

  condition:
    any of them
}