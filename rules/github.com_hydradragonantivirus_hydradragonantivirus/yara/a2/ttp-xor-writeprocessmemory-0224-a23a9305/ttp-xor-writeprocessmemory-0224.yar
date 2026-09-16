rule TTP_XOR_WriteProcessMemory_0224 {
  strings:
    $key_0224 = { 55 56 [2] 67 74 [2] 61 41 [2] 4f 41 [2] 70 5d }

  condition:
    any of them
}