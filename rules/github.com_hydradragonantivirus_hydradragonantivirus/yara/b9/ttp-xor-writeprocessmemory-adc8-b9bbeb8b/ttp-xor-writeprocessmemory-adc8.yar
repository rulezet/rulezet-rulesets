rule TTP_XOR_WriteProcessMemory_adc8 {
  strings:
    $key_adc8 = { fa ba [2] c8 98 [2] ce ad [2] e0 ad [2] df b1 }

  condition:
    any of them
}