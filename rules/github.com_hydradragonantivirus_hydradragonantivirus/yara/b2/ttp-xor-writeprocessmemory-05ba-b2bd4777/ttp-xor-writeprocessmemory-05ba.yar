rule TTP_XOR_WriteProcessMemory_05ba {
  strings:
    $key_05ba = { 52 c8 [2] 60 ea [2] 66 df [2] 48 df [2] 77 c3 }

  condition:
    any of them
}