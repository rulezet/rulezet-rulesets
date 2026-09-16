rule TTP_XOR_WriteProcessMemory_f333 {
  strings:
    $key_f333 = { a4 41 [2] 96 63 [2] 90 56 [2] be 56 [2] 81 4a }

  condition:
    any of them
}