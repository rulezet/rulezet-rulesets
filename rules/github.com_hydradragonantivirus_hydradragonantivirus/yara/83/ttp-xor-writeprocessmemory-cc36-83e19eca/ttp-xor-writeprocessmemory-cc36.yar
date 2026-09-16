rule TTP_XOR_WriteProcessMemory_cc36 {
  strings:
    $key_cc36 = { 9b 44 [2] a9 66 [2] af 53 [2] 81 53 [2] be 4f }

  condition:
    any of them
}