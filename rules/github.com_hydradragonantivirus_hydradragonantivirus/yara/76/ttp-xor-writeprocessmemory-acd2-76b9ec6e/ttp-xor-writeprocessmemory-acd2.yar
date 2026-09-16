rule TTP_XOR_WriteProcessMemory_acd2 {
  strings:
    $key_acd2 = { fb a0 [2] c9 82 [2] cf b7 [2] e1 b7 [2] de ab }

  condition:
    any of them
}