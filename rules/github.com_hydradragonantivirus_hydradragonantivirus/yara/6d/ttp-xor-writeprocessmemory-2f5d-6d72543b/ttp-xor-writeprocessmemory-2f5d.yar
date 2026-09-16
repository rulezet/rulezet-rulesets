rule TTP_XOR_WriteProcessMemory_2f5d {
  strings:
    $key_2f5d = { 78 2f [2] 4a 0d [2] 4c 38 [2] 62 38 [2] 5d 24 }

  condition:
    any of them
}