rule TTP_XOR_WriteProcessMemory_bda3 {
  strings:
    $key_bda3 = { ea d1 [2] d8 f3 [2] de c6 [2] f0 c6 [2] cf da }

  condition:
    any of them
}