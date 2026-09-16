rule TTP_XOR_WriteProcessMemory_569a {
  strings:
    $key_569a = { 01 e8 [2] 33 ca [2] 35 ff [2] 1b ff [2] 24 e3 }

  condition:
    any of them
}