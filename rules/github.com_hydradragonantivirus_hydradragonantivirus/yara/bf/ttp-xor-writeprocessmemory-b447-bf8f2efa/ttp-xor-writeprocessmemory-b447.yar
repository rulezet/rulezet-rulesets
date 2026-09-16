rule TTP_XOR_WriteProcessMemory_b447 {
  strings:
    $key_b447 = { e3 35 [2] d1 17 [2] d7 22 [2] f9 22 [2] c6 3e }

  condition:
    any of them
}