rule TTP_XOR_WriteProcessMemory_359a {
  strings:
    $key_359a = { 62 e8 [2] 50 ca [2] 56 ff [2] 78 ff [2] 47 e3 }

  condition:
    any of them
}