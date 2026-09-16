rule TTP_XOR_WriteProcessMemory_f360 {
  strings:
    $key_f360 = { a4 12 [2] 96 30 [2] 90 05 [2] be 05 [2] 81 19 }

  condition:
    any of them
}