rule TTP_XOR_WriteProcessMemory_e415 {
  strings:
    $key_e415 = { b3 67 [2] 81 45 [2] 87 70 [2] a9 70 [2] 96 6c }

  condition:
    any of them
}