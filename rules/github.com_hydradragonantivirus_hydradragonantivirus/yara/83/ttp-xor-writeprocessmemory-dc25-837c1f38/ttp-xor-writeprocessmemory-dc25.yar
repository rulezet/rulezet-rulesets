rule TTP_XOR_WriteProcessMemory_dc25 {
  strings:
    $key_dc25 = { 8b 57 [2] b9 75 [2] bf 40 [2] 91 40 [2] ae 5c }

  condition:
    any of them
}