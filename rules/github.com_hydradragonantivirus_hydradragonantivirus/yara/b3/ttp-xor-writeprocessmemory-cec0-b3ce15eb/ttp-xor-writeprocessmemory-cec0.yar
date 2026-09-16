rule TTP_XOR_WriteProcessMemory_cec0 {
  strings:
    $key_cec0 = { 99 b2 [2] ab 90 [2] ad a5 [2] 83 a5 [2] bc b9 }

  condition:
    any of them
}