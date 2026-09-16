rule TTP_XOR_WriteProcessMemory_0ad4 {
  strings:
    $key_0ad4 = { 5d a6 [2] 6f 84 [2] 69 b1 [2] 47 b1 [2] 78 ad }

  condition:
    any of them
}