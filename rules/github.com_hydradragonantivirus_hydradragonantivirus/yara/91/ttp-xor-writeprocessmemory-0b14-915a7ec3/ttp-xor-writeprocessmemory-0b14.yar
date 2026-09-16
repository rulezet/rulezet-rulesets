rule TTP_XOR_WriteProcessMemory_0b14 {
  strings:
    $key_0b14 = { 5c 66 [2] 6e 44 [2] 68 71 [2] 46 71 [2] 79 6d }

  condition:
    any of them
}