rule TTP_XOR_WriteProcessMemory_49ba {
  strings:
    $key_49ba = { 1e c8 [2] 2c ea [2] 2a df [2] 04 df [2] 3b c3 }

  condition:
    any of them
}