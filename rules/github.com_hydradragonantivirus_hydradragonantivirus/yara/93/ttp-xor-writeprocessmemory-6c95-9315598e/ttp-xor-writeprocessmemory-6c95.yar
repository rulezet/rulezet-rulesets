rule TTP_XOR_WriteProcessMemory_6c95 {
  strings:
    $key_6c95 = { 3b e7 [2] 09 c5 [2] 0f f0 [2] 21 f0 [2] 1e ec }

  condition:
    any of them
}