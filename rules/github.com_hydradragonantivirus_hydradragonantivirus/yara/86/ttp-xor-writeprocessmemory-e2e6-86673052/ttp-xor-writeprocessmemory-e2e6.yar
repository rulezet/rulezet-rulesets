rule TTP_XOR_WriteProcessMemory_e2e6 {
  strings:
    $key_e2e6 = { b5 94 [2] 87 b6 [2] 81 83 [2] af 83 [2] 90 9f }

  condition:
    any of them
}