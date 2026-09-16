rule TTP_XOR_WriteProcessMemory_2f0d {
  strings:
    $key_2f0d = { 78 7f [2] 4a 5d [2] 4c 68 [2] 62 68 [2] 5d 74 }

  condition:
    any of them
}