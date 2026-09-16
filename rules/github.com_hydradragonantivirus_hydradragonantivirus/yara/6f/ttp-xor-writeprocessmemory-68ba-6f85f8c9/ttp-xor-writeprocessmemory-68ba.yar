rule TTP_XOR_WriteProcessMemory_68ba {
  strings:
    $key_68ba = { 3f c8 [2] 0d ea [2] 0b df [2] 25 df [2] 1a c3 }

  condition:
    any of them
}