rule TTP_XOR_WriteProcessMemory_c8d3 {
  strings:
    $key_c8d3 = { 9f a1 [2] ad 83 [2] ab b6 [2] 85 b6 [2] ba aa }

  condition:
    any of them
}