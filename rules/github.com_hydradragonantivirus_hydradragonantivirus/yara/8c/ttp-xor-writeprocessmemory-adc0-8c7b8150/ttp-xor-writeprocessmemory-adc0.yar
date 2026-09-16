rule TTP_XOR_WriteProcessMemory_adc0 {
  strings:
    $key_adc0 = { fa b2 [2] c8 90 [2] ce a5 [2] e0 a5 [2] df b9 }

  condition:
    any of them
}