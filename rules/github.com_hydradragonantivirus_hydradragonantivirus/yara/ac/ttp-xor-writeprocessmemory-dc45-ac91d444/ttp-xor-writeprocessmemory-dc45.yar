rule TTP_XOR_WriteProcessMemory_dc45 {
  strings:
    $key_dc45 = { 8b 37 [2] b9 15 [2] bf 20 [2] 91 20 [2] ae 3c }

  condition:
    any of them
}