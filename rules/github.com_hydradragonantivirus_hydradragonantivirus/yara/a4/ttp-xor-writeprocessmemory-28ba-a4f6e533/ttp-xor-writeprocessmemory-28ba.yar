rule TTP_XOR_WriteProcessMemory_28ba {
  strings:
    $key_28ba = { 7f c8 [2] 4d ea [2] 4b df [2] 65 df [2] 5a c3 }

  condition:
    any of them
}