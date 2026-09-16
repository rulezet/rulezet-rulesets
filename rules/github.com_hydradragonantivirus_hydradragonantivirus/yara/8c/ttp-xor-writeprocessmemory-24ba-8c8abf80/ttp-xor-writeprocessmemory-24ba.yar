rule TTP_XOR_WriteProcessMemory_24ba {
  strings:
    $key_24ba = { 73 c8 [2] 41 ea [2] 47 df [2] 69 df [2] 56 c3 }

  condition:
    any of them
}