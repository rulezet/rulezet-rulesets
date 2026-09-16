rule TTP_XOR_WriteProcessMemory_668f {
  strings:
    $key_668f = { 31 fd [2] 03 df [2] 05 ea [2] 2b ea [2] 14 f6 }

  condition:
    any of them
}