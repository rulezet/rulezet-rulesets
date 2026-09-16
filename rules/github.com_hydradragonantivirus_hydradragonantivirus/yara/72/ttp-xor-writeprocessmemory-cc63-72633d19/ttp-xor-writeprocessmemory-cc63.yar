rule TTP_XOR_WriteProcessMemory_cc63 {
  strings:
    $key_cc63 = { 9b 11 [2] a9 33 [2] af 06 [2] 81 06 [2] be 1a }

  condition:
    any of them
}