rule TTP_XOR_WriteProcessMemory_cc64 {
  strings:
    $key_cc64 = { 9b 16 [2] a9 34 [2] af 01 [2] 81 01 [2] be 1d }

  condition:
    any of them
}