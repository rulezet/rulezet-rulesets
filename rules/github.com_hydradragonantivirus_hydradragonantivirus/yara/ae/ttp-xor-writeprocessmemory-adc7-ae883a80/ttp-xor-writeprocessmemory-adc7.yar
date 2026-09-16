rule TTP_XOR_WriteProcessMemory_adc7 {
  strings:
    $key_adc7 = { fa b5 [2] c8 97 [2] ce a2 [2] e0 a2 [2] df be }

  condition:
    any of them
}