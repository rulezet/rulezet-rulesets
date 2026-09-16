rule TTP_XOR_WriteProcessMemory_cc33 {
  strings:
    $key_cc33 = { 9b 41 [2] a9 63 [2] af 56 [2] 81 56 [2] be 4a }

  condition:
    any of them
}