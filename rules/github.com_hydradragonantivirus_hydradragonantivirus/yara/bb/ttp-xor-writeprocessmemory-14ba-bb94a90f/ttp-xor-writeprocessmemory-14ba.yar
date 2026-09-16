rule TTP_XOR_WriteProcessMemory_14ba {
  strings:
    $key_14ba = { 43 c8 [2] 71 ea [2] 77 df [2] 59 df [2] 66 c3 }

  condition:
    any of them
}