rule TTP_XOR_WriteProcessMemory_dcc8 {
  strings:
    $key_dcc8 = { 8b ba [2] b9 98 [2] bf ad [2] 91 ad [2] ae b1 }

  condition:
    any of them
}