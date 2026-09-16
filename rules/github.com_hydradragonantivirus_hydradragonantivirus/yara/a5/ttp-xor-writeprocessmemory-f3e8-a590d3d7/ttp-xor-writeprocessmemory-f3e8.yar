rule TTP_XOR_WriteProcessMemory_f3e8 {
  strings:
    $key_f3e8 = { a4 9a [2] 96 b8 [2] 90 8d [2] be 8d [2] 81 91 }

  condition:
    any of them
}