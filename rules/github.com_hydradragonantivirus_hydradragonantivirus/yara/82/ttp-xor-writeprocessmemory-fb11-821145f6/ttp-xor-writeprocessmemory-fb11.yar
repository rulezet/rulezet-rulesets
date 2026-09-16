rule TTP_XOR_WriteProcessMemory_fb11 {
  strings:
    $key_fb11 = { ac 63 [2] 9e 41 [2] 98 74 [2] b6 74 [2] 89 68 }

  condition:
    any of them
}