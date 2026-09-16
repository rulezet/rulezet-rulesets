rule TTP_XOR_WriteProcessMemory_1cba {
  strings:
    $key_1cba = { 4b c8 [2] 79 ea [2] 7f df [2] 51 df [2] 6e c3 }

  condition:
    any of them
}