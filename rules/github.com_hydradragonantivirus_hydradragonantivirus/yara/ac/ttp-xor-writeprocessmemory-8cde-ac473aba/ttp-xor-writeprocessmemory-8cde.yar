rule TTP_XOR_WriteProcessMemory_8cde {
  strings:
    $key_8cde = { db ac [2] e9 8e [2] ef bb [2] c1 bb [2] fe a7 }

  condition:
    any of them
}