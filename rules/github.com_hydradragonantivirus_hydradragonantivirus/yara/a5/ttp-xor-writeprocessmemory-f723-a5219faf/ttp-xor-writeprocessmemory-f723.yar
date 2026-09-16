rule TTP_XOR_WriteProcessMemory_f723 {
  strings:
    $key_f723 = { a0 51 [2] 92 73 [2] 94 46 [2] ba 46 [2] 85 5a }

  condition:
    any of them
}