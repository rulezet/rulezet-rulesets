rule TTP_XOR_WriteProcessMemory_2452 {
  strings:
    $key_2452 = { 73 20 [2] 41 02 [2] 47 37 [2] 69 37 [2] 56 2b }

  condition:
    any of them
}