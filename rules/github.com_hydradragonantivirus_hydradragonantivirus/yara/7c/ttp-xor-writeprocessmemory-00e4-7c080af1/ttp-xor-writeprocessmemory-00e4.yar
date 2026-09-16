rule TTP_XOR_WriteProcessMemory_00e4 {
  strings:
    $key_00e4 = { 57 96 [2] 65 b4 [2] 63 81 [2] 4d 81 [2] 72 9d }

  condition:
    any of them
}