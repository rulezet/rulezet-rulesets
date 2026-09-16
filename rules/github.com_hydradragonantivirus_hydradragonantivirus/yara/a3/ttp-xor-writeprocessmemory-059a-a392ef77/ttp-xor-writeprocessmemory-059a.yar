rule TTP_XOR_WriteProcessMemory_059a {
  strings:
    $key_059a = { 52 e8 [2] 60 ca [2] 66 ff [2] 48 ff [2] 77 e3 }

  condition:
    any of them
}