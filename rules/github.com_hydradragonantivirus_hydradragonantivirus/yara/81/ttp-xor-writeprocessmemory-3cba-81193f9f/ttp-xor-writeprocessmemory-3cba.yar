rule TTP_XOR_WriteProcessMemory_3cba {
  strings:
    $key_3cba = { 6b c8 [2] 59 ea [2] 5f df [2] 71 df [2] 4e c3 }

  condition:
    any of them
}