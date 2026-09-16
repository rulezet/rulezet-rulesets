rule TTP_XOR_WriteProcessMemory_adc9 {
  strings:
    $key_adc9 = { fa bb [2] c8 99 [2] ce ac [2] e0 ac [2] df b0 }

  condition:
    any of them
}