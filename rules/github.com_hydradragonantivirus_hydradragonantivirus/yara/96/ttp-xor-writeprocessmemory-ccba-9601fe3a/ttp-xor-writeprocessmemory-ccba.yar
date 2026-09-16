rule TTP_XOR_WriteProcessMemory_ccba {
  strings:
    $key_ccba = { 9b c8 [2] a9 ea [2] af df [2] 81 df [2] be c3 }

  condition:
    any of them
}