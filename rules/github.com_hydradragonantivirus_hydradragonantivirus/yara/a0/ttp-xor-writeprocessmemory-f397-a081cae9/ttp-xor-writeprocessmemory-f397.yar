rule TTP_XOR_WriteProcessMemory_f397 {
  strings:
    $key_f397 = { a4 e5 [2] 96 c7 [2] 90 f2 [2] be f2 [2] 81 ee }

  condition:
    any of them
}