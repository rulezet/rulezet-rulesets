rule TTP_XOR_WriteProcessMemory_f304 {
  strings:
    $key_f304 = { a4 76 [2] 96 54 [2] 90 61 [2] be 61 [2] 81 7d }

  condition:
    any of them
}