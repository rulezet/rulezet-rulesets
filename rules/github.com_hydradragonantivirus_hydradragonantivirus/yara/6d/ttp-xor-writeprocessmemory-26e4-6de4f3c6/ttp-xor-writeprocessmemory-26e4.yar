rule TTP_XOR_WriteProcessMemory_26e4 {
  strings:
    $key_26e4 = { 71 96 [2] 43 b4 [2] 45 81 [2] 6b 81 [2] 54 9d }

  condition:
    any of them
}