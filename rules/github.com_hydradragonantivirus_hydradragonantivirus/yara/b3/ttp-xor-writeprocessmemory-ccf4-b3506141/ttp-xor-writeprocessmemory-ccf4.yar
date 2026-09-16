rule TTP_XOR_WriteProcessMemory_ccf4 {
  strings:
    $key_ccf4 = { 9b 86 [2] a9 a4 [2] af 91 [2] 81 91 [2] be 8d }

  condition:
    any of them
}