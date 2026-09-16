rule TTP_XOR_WriteProcessMemory_6710 {
  strings:
    $key_6710 = { 30 62 [2] 02 40 [2] 04 75 [2] 2a 75 [2] 15 69 }

  condition:
    any of them
}