rule TTP_XOR_WriteProcessMemory_079a {
  strings:
    $key_079a = { 50 e8 [2] 62 ca [2] 64 ff [2] 4a ff [2] 75 e3 }

  condition:
    any of them
}