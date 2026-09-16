rule TTP_XOR_WriteProcessMemory_f39a {
  strings:
    $key_f39a = { a4 e8 [2] 96 ca [2] 90 ff [2] be ff [2] 81 e3 }

  condition:
    any of them
}