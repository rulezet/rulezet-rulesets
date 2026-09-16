rule TTP_XOR_WriteProcessMemory_e2e2 {
  strings:
    $key_e2e2 = { b5 90 [2] 87 b2 [2] 81 87 [2] af 87 [2] 90 9b }

  condition:
    any of them
}