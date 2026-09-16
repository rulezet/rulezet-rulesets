rule TTP_XOR_WriteProcessMemory_41e4 {
  strings:
    $key_41e4 = { 16 96 [2] 24 b4 [2] 22 81 [2] 0c 81 [2] 33 9d }

  condition:
    any of them
}