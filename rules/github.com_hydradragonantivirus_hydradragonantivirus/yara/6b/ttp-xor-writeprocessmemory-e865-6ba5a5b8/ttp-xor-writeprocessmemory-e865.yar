rule TTP_XOR_WriteProcessMemory_e865 {
  strings:
    $key_e865 = { bf 17 [2] 8d 35 [2] 8b 00 [2] a5 00 [2] 9a 1c }

  condition:
    any of them
}