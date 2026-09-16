rule TTP_XOR_WriteProcessMemory_e251 {
  strings:
    $key_e251 = { b5 23 [2] 87 01 [2] 81 34 [2] af 34 [2] 90 28 }

  condition:
    any of them
}