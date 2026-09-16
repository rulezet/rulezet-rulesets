rule TTP_XOR_WriteProcessMemory_f371 {
  strings:
    $key_f371 = { a4 03 [2] 96 21 [2] 90 14 [2] be 14 [2] 81 08 }

  condition:
    any of them
}