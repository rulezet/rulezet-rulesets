rule TTP_XOR_WriteProcessMemory_e236 {
  strings:
    $key_e236 = { b5 44 [2] 87 66 [2] 81 53 [2] af 53 [2] 90 4f }

  condition:
    any of them
}