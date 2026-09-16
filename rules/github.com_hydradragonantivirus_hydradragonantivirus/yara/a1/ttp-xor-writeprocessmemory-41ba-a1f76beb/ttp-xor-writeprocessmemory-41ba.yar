rule TTP_XOR_WriteProcessMemory_41ba {
  strings:
    $key_41ba = { 16 c8 [2] 24 ea [2] 22 df [2] 0c df [2] 33 c3 }

  condition:
    any of them
}