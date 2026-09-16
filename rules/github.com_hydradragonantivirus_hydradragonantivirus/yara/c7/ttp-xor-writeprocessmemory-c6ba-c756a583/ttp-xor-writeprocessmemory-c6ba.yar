rule TTP_XOR_WriteProcessMemory_c6ba {
  strings:
    $key_c6ba = { 91 c8 [2] a3 ea [2] a5 df [2] 8b df [2] b4 c3 }

  condition:
    any of them
}