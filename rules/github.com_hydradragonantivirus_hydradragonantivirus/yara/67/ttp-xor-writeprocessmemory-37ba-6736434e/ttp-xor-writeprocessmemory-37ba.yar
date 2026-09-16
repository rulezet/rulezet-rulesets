rule TTP_XOR_WriteProcessMemory_37ba {
  strings:
    $key_37ba = { 60 c8 [2] 52 ea [2] 54 df [2] 7a df [2] 45 c3 }

  condition:
    any of them
}