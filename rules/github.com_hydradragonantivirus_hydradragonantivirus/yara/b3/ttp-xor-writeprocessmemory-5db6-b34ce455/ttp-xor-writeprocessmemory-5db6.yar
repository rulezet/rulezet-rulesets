rule TTP_XOR_WriteProcessMemory_5db6 {
  strings:
    $key_5db6 = { 0a c4 [2] 38 e6 [2] 3e d3 [2] 10 d3 [2] 2f cf }

  condition:
    any of them
}