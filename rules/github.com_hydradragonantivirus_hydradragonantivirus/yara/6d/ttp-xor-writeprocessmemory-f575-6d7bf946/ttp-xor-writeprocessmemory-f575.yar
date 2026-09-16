rule TTP_XOR_WriteProcessMemory_f575 {
  strings:
    $key_f575 = { a2 07 [2] 90 25 [2] 96 10 [2] b8 10 [2] 87 0c }

  condition:
    any of them
}