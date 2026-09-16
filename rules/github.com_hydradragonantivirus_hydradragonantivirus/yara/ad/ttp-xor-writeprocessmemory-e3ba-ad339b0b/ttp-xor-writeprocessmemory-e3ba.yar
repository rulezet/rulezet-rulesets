rule TTP_XOR_WriteProcessMemory_e3ba {
  strings:
    $key_e3ba = { b4 c8 [2] 86 ea [2] 80 df [2] ae df [2] 91 c3 }

  condition:
    any of them
}