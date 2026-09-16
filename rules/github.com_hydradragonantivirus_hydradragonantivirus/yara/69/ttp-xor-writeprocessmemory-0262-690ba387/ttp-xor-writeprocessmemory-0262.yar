rule TTP_XOR_WriteProcessMemory_0262 {
  strings:
    $key_0262 = { 55 10 [2] 67 32 [2] 61 07 [2] 4f 07 [2] 70 1b }

  condition:
    any of them
}