rule TTP_XOR_WriteProcessMemory_cc66 {
  strings:
    $key_cc66 = { 9b 14 [2] a9 36 [2] af 03 [2] 81 03 [2] be 1f }

  condition:
    any of them
}