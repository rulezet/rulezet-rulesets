rule TTP_XOR_WriteProcessMemory_4cd4 {
  strings:
    $key_4cd4 = { 1b a6 [2] 29 84 [2] 2f b1 [2] 01 b1 [2] 3e ad }

  condition:
    any of them
}