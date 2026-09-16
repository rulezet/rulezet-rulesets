rule TTP_XOR_WriteProcessMemory_d8ba {
  strings:
    $key_d8ba = { 8f c8 [2] bd ea [2] bb df [2] 95 df [2] aa c3 }

  condition:
    any of them
}