rule TTP_XOR_WriteProcessMemory_cc00 {
  strings:
    $key_cc00 = { 9b 72 [2] a9 50 [2] af 65 [2] 81 65 [2] be 79 }

  condition:
    any of them
}