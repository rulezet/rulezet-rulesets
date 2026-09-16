rule TTP_XOR_WriteProcessMemory_f3f4 {
  strings:
    $key_f3f4 = { a4 86 [2] 96 a4 [2] 90 91 [2] be 91 [2] 81 8d }

  condition:
    any of them
}