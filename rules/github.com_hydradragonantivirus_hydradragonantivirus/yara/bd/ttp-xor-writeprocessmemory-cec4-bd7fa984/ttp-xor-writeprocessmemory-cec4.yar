rule TTP_XOR_WriteProcessMemory_cec4 {
  strings:
    $key_cec4 = { 99 b6 [2] ab 94 [2] ad a1 [2] 83 a1 [2] bc bd }

  condition:
    any of them
}