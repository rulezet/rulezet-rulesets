rule TTP_XOR_WriteProcessMemory_fb95 {
  strings:
    $key_fb95 = { ac e7 [2] 9e c5 [2] 98 f0 [2] b6 f0 [2] 89 ec }

  condition:
    any of them
}