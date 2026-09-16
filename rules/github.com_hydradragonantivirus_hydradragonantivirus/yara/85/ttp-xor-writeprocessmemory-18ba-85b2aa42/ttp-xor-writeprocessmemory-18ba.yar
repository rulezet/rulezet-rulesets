rule TTP_XOR_WriteProcessMemory_18ba {
  strings:
    $key_18ba = { 4f c8 [2] 7d ea [2] 7b df [2] 55 df [2] 6a c3 }

  condition:
    any of them
}