rule TTP_XOR_WriteProcessMemory_5cba {
  strings:
    $key_5cba = { 0b c8 [2] 39 ea [2] 3f df [2] 11 df [2] 2e c3 }

  condition:
    any of them
}