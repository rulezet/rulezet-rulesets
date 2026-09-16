rule TTP_XOR_WriteProcessMemory_56ba {
  strings:
    $key_56ba = { 01 c8 [2] 33 ea [2] 35 df [2] 1b df [2] 24 c3 }

  condition:
    any of them
}