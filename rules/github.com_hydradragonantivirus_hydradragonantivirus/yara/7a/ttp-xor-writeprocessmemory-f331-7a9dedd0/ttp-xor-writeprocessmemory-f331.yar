rule TTP_XOR_WriteProcessMemory_f331 {
  strings:
    $key_f331 = { a4 43 [2] 96 61 [2] 90 54 [2] be 54 [2] 81 48 }

  condition:
    any of them
}