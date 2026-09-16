rule TTP_XOR_WriteProcessMemory_dc35 {
  strings:
    $key_dc35 = { 8b 47 [2] b9 65 [2] bf 50 [2] 91 50 [2] ae 4c }

  condition:
    any of them
}