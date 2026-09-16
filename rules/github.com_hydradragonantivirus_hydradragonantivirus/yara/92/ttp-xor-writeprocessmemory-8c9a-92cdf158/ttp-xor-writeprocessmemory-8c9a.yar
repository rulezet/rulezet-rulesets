rule TTP_XOR_WriteProcessMemory_8c9a {
  strings:
    $key_8c9a = { db e8 [2] e9 ca [2] ef ff [2] c1 ff [2] fe e3 }

  condition:
    any of them
}