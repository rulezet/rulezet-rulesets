rule TTP_XOR_WriteProcessMemory_f545 {
  strings:
    $key_f545 = { a2 37 [2] 90 15 [2] 96 20 [2] b8 20 [2] 87 3c }

  condition:
    any of them
}