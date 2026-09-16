rule TTP_XOR_WriteProcessMemory_cc53 {
  strings:
    $key_cc53 = { 9b 21 [2] a9 03 [2] af 36 [2] 81 36 [2] be 2a }

  condition:
    any of them
}