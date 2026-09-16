rule TTP_XOR_WriteProcessMemory_f349 {
  strings:
    $key_f349 = { a4 3b [2] 96 19 [2] 90 2c [2] be 2c [2] 81 30 }

  condition:
    any of them
}