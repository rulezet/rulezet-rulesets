rule TTP_XOR_WriteProcessMemory_e276 {
  strings:
    $key_e276 = { b5 04 [2] 87 26 [2] 81 13 [2] af 13 [2] 90 0f }

  condition:
    any of them
}