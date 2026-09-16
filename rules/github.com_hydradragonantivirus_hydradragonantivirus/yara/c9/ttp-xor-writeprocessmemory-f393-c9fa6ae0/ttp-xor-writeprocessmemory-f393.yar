rule TTP_XOR_WriteProcessMemory_f393 {
  strings:
    $key_f393 = { a4 e1 [2] 96 c3 [2] 90 f6 [2] be f6 [2] 81 ea }

  condition:
    any of them
}