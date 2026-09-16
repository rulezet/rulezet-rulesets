rule TTP_XOR_WriteProcessMemory_0124 {
  strings:
    $key_0124 = { 56 56 [2] 64 74 [2] 62 41 [2] 4c 41 [2] 73 5d }

  condition:
    any of them
}