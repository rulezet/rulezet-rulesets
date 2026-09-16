rule TTP_XOR_WriteProcessMemory_cc30 {
  strings:
    $key_cc30 = { 9b 42 [2] a9 60 [2] af 55 [2] 81 55 [2] be 49 }

  condition:
    any of them
}