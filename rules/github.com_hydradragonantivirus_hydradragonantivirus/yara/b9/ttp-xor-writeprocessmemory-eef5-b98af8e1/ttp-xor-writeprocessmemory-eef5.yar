rule TTP_XOR_WriteProcessMemory_eef5 {
  strings:
    $key_eef5 = { b9 87 [2] 8b a5 [2] 8d 90 [2] a3 90 [2] 9c 8c }

  condition:
    any of them
}