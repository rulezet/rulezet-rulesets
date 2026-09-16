rule TTP_XOR_WriteProcessMemory_e053 {
  strings:
    $key_e053 = { b7 21 [2] 85 03 [2] 83 36 [2] ad 36 [2] 92 2a }

  condition:
    any of them
}