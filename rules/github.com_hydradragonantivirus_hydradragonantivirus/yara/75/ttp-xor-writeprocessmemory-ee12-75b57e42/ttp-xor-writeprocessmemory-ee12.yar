rule TTP_XOR_WriteProcessMemory_ee12 {
  strings:
    $key_ee12 = { b9 60 [2] 8b 42 [2] 8d 77 [2] a3 77 [2] 9c 6b }

  condition:
    any of them
}