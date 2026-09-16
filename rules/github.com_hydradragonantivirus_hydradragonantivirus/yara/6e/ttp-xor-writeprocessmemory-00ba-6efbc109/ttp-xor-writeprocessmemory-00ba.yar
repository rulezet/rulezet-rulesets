rule TTP_XOR_WriteProcessMemory_00ba {
  strings:
    $key_00ba = { 57 c8 [2] 65 ea [2] 63 df [2] 4d df [2] 72 c3 }

  condition:
    any of them
}