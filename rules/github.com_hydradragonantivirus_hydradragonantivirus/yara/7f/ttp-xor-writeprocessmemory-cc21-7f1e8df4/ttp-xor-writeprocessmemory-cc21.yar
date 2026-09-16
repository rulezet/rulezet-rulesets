rule TTP_XOR_WriteProcessMemory_cc21 {
  strings:
    $key_cc21 = { 9b 53 [2] a9 71 [2] af 44 [2] 81 44 [2] be 58 }

  condition:
    any of them
}