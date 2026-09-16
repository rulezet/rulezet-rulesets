rule TTP_XOR_WriteProcessMemory_b265 {
  strings:
    $key_b265 = { e5 17 [2] d7 35 [2] d1 00 [2] ff 00 [2] c0 1c }

  condition:
    any of them
}