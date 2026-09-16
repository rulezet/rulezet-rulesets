rule TTP_XOR_WriteProcessMemory_5c95 {
  strings:
    $key_5c95 = { 0b e7 [2] 39 c5 [2] 3f f0 [2] 11 f0 [2] 2e ec }

  condition:
    any of them
}