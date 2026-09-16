rule TTP_XOR_WriteProcessMemory_849a {
  strings:
    $key_849a = { d3 e8 [2] e1 ca [2] e7 ff [2] c9 ff [2] f6 e3 }

  condition:
    any of them
}