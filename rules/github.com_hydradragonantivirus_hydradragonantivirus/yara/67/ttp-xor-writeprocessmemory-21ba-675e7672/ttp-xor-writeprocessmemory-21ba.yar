rule TTP_XOR_WriteProcessMemory_21ba {
  strings:
    $key_21ba = { 76 c8 [2] 44 ea [2] 42 df [2] 6c df [2] 53 c3 }

  condition:
    any of them
}