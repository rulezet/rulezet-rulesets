rule TTP_XOR_WriteProcessMemory_cc74 {
  strings:
    $key_cc74 = { 9b 06 [2] a9 24 [2] af 11 [2] 81 11 [2] be 0d }

  condition:
    any of them
}