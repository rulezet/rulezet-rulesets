rule TTP_XOR_WriteProcessMemory_adcb {
  strings:
    $key_adcb = { fa b9 [2] c8 9b [2] ce ae [2] e0 ae [2] df b2 }

  condition:
    any of them
}