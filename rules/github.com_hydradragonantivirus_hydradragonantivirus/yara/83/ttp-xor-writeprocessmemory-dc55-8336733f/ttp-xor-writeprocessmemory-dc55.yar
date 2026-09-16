rule TTP_XOR_WriteProcessMemory_dc55 {
  strings:
    $key_dc55 = { 8b 27 [2] b9 05 [2] bf 30 [2] 91 30 [2] ae 2c }

  condition:
    any of them
}