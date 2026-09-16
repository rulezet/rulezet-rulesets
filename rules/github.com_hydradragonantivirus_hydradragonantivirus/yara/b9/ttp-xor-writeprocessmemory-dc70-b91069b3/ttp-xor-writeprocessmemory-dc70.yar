rule TTP_XOR_WriteProcessMemory_dc70 {
  strings:
    $key_dc70 = { 8b 02 [2] b9 20 [2] bf 15 [2] 91 15 [2] ae 09 }

  condition:
    any of them
}