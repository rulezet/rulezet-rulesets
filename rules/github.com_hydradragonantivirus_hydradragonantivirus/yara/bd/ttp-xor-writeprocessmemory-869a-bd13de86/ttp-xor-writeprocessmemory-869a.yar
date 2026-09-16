rule TTP_XOR_WriteProcessMemory_869a {
  strings:
    $key_869a = { d1 e8 [2] e3 ca [2] e5 ff [2] cb ff [2] f4 e3 }

  condition:
    any of them
}