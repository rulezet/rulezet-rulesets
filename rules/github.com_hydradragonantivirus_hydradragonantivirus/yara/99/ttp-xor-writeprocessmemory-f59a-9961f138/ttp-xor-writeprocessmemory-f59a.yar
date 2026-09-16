rule TTP_XOR_WriteProcessMemory_f59a {
  strings:
    $key_f59a = { a2 e8 [2] 90 ca [2] 96 ff [2] b8 ff [2] 87 e3 }

  condition:
    any of them
}