rule TTP_XOR_WriteProcessMemory_2f33 {
  strings:
    $key_2f33 = { 78 41 [2] 4a 63 [2] 4c 56 [2] 62 56 [2] 5d 4a }

  condition:
    any of them
}