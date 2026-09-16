rule TTP_XOR_WriteProcessMemory_e8ba {
  strings:
    $key_e8ba = { bf c8 [2] 8d ea [2] 8b df [2] a5 df [2] 9a c3 }

  condition:
    any of them
}