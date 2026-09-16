rule TTP_XOR_WriteProcessMemory_2710 {
  strings:
    $key_2710 = { 70 62 [2] 42 40 [2] 44 75 [2] 6a 75 [2] 55 69 }

  condition:
    any of them
}