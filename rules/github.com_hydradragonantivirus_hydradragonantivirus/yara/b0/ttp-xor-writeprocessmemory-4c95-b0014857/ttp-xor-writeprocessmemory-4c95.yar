rule TTP_XOR_WriteProcessMemory_4c95 {
  strings:
    $key_4c95 = { 1b e7 [2] 29 c5 [2] 2f f0 [2] 01 f0 [2] 3e ec }

  condition:
    any of them
}