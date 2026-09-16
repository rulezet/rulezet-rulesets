rule TTP_XOR_WriteProcessMemory_f369 {
  strings:
    $key_f369 = { a4 1b [2] 96 39 [2] 90 0c [2] be 0c [2] 81 10 }

  condition:
    any of them
}