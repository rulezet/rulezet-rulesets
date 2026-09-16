rule TTP_XOR_WriteProcessMemory_1b14 {
  strings:
    $key_1b14 = { 4c 66 [2] 7e 44 [2] 78 71 [2] 56 71 [2] 69 6d }

  condition:
    any of them
}