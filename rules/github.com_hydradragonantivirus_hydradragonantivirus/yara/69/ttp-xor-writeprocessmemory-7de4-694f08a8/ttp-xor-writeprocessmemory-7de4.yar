rule TTP_XOR_WriteProcessMemory_7de4 {
  strings:
    $key_7de4 = { 2a 96 [2] 18 b4 [2] 1e 81 [2] 30 81 [2] 0f 9d }

  condition:
    any of them
}