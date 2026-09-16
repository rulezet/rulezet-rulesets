rule TTP_XOR_WriteProcessMemory_e9ba {
  strings:
    $key_e9ba = { be c8 [2] 8c ea [2] 8a df [2] a4 df [2] 9b c3 }

  condition:
    any of them
}