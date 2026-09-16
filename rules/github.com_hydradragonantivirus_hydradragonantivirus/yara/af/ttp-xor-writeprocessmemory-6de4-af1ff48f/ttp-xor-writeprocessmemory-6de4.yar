rule TTP_XOR_WriteProcessMemory_6de4 {
  strings:
    $key_6de4 = { 3a 96 [2] 08 b4 [2] 0e 81 [2] 20 81 [2] 1f 9d }

  condition:
    any of them
}