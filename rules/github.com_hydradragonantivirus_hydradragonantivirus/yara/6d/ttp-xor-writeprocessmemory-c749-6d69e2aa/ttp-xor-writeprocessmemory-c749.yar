rule TTP_XOR_WriteProcessMemory_c749 {
  strings:
    $key_c749 = { 90 3b [2] a2 19 [2] a4 2c [2] 8a 2c [2] b5 30 }

  condition:
    any of them
}