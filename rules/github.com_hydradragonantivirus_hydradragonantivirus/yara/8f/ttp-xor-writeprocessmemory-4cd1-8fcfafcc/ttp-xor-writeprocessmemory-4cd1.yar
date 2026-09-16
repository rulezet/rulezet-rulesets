rule TTP_XOR_WriteProcessMemory_4cd1 {
  strings:
    $key_4cd1 = { 1b a3 [2] 29 81 [2] 2f b4 [2] 01 b4 [2] 3e a8 }

  condition:
    any of them
}