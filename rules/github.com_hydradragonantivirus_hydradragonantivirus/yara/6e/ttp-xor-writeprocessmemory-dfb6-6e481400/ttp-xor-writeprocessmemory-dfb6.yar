rule TTP_XOR_WriteProcessMemory_dfb6 {
  strings:
    $key_dfb6 = { 88 c4 [2] ba e6 [2] bc d3 [2] 92 d3 [2] ad cf }

  condition:
    any of them
}