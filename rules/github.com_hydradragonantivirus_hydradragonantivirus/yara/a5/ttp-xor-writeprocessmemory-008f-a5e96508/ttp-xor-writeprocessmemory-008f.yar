rule TTP_XOR_WriteProcessMemory_008f {
  strings:
    $key_008f = { 57 fd [2] 65 df [2] 63 ea [2] 4d ea [2] 72 f6 }

  condition:
    any of them
}