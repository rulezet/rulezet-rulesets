rule TTP_XOR_WriteProcessMemory_f771 {
  strings:
    $key_f771 = { a0 03 [2] 92 21 [2] 94 14 [2] ba 14 [2] 85 08 }

  condition:
    any of them
}