rule TTP_XOR_WriteProcessMemory_f544 {
  strings:
    $key_f544 = { a2 36 [2] 90 14 [2] 96 21 [2] b8 21 [2] 87 3d }

  condition:
    any of them
}