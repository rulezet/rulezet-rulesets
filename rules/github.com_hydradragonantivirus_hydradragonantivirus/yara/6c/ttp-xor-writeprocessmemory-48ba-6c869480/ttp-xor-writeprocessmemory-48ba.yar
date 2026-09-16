rule TTP_XOR_WriteProcessMemory_48ba {
  strings:
    $key_48ba = { 1f c8 [2] 2d ea [2] 2b df [2] 05 df [2] 3a c3 }

  condition:
    any of them
}