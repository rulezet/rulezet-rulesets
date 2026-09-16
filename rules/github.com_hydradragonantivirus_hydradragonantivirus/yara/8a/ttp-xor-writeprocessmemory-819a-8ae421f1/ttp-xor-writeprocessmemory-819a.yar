rule TTP_XOR_WriteProcessMemory_819a {
  strings:
    $key_819a = { d6 e8 [2] e4 ca [2] e2 ff [2] cc ff [2] f3 e3 }

  condition:
    any of them
}