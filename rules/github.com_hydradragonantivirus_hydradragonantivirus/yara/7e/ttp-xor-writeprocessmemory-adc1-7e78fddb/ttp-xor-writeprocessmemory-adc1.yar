rule TTP_XOR_WriteProcessMemory_adc1 {
  strings:
    $key_adc1 = { fa b3 [2] c8 91 [2] ce a4 [2] e0 a4 [2] df b8 }

  condition:
    any of them
}