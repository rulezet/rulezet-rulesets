rule TTP_XOR_WriteProcessMemory_20ba {
  strings:
    $key_20ba = { 77 c8 [2] 45 ea [2] 43 df [2] 6d df [2] 52 c3 }

  condition:
    any of them
}