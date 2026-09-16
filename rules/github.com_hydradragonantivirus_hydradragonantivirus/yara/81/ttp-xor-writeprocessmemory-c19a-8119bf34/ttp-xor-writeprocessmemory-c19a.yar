rule TTP_XOR_WriteProcessMemory_c19a {
  strings:
    $key_c19a = { 96 e8 [2] a4 ca [2] a2 ff [2] 8c ff [2] b3 e3 }

  condition:
    any of them
}