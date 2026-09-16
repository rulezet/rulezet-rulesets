rule TTP_XOR_WriteProcessMemory_f524 {
  strings:
    $key_f524 = { a2 56 [2] 90 74 [2] 96 41 [2] b8 41 [2] 87 5d }

  condition:
    any of them
}