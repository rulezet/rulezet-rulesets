rule TTP_XOR_WriteProcessMemory_16ba {
  strings:
    $key_16ba = { 41 c8 [2] 73 ea [2] 75 df [2] 5b df [2] 64 c3 }

  condition:
    any of them
}