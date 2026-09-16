rule TTP_XOR_WriteProcessMemory_01e4 {
  strings:
    $key_01e4 = { 56 96 [2] 64 b4 [2] 62 81 [2] 4c 81 [2] 73 9d }

  condition:
    any of them
}