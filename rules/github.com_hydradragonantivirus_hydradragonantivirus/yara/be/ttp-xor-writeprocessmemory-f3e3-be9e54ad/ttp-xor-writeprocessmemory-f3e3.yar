rule TTP_XOR_WriteProcessMemory_f3e3 {
  strings:
    $key_f3e3 = { a4 91 [2] 96 b3 [2] 90 86 [2] be 86 [2] 81 9a }

  condition:
    any of them
}