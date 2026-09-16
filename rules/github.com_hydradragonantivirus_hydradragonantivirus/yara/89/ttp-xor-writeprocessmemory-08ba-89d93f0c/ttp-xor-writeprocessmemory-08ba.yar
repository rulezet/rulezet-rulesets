rule TTP_XOR_WriteProcessMemory_08ba {
  strings:
    $key_08ba = { 5f c8 [2] 6d ea [2] 6b df [2] 45 df [2] 7a c3 }

  condition:
    any of them
}