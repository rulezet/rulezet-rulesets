rule TTP_XOR_WriteProcessMemory_69ba {
  strings:
    $key_69ba = { 3e c8 [2] 0c ea [2] 0a df [2] 24 df [2] 1b c3 }

  condition:
    any of them
}