rule TTP_XOR_WriteProcessMemory_cc20 {
  strings:
    $key_cc20 = { 9b 52 [2] a9 70 [2] af 45 [2] 81 45 [2] be 59 }

  condition:
    any of them
}