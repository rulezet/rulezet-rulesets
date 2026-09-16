rule TTP_XOR_WriteProcessMemory_05e4 {
  strings:
    $key_05e4 = { 52 96 [2] 60 b4 [2] 66 81 [2] 48 81 [2] 77 9d }

  condition:
    any of them
}