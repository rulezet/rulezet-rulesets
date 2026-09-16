rule TTP_XOR_WriteProcessMemory_2ab2 {
  strings:
    $key_2ab2 = { 7d c0 [2] 4f e2 [2] 49 d7 [2] 67 d7 [2] 58 cb }

  condition:
    any of them
}