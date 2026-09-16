rule TTP_XOR_WriteProcessMemory_6db6 {
  strings:
    $key_6db6 = { 3a c4 [2] 08 e6 [2] 0e d3 [2] 20 d3 [2] 1f cf }

  condition:
    any of them
}