rule TTP_XOR_WriteProcessMemory_abb9 {
  strings:
    $key_abb9 = { fc cb [2] ce e9 [2] c8 dc [2] e6 dc [2] d9 c0 }

  condition:
    any of them
}