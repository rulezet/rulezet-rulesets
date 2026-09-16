rule TTP_XOR_WriteProcessMemory_71ba {
  strings:
    $key_71ba = { 26 c8 [2] 14 ea [2] 12 df [2] 3c df [2] 03 c3 }

  condition:
    any of them
}