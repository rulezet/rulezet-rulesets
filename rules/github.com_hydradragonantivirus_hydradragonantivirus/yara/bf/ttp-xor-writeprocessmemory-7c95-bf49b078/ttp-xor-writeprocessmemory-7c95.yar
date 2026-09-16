rule TTP_XOR_WriteProcessMemory_7c95 {
  strings:
    $key_7c95 = { 2b e7 [2] 19 c5 [2] 1f f0 [2] 31 f0 [2] 0e ec }

  condition:
    any of them
}