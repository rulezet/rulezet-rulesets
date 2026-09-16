rule TTP_XOR_WriteProcessMemory_248f {
  strings:
    $key_248f = { 73 fd [2] 41 df [2] 47 ea [2] 69 ea [2] 56 f6 }

  condition:
    any of them
}