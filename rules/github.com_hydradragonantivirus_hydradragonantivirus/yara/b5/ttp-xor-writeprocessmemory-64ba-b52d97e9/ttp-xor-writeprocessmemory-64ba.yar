rule TTP_XOR_WriteProcessMemory_64ba {
  strings:
    $key_64ba = { 33 c8 [2] 01 ea [2] 07 df [2] 29 df [2] 16 c3 }

  condition:
    any of them
}