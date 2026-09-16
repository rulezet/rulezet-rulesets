rule TTP_XOR_WriteProcessMemory_03ba {
  strings:
    $key_03ba = { 54 c8 [2] 66 ea [2] 60 df [2] 4e df [2] 71 c3 }

  condition:
    any of them
}