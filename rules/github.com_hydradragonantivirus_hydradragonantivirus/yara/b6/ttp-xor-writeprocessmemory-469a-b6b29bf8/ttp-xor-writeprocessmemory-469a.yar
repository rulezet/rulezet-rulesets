rule TTP_XOR_WriteProcessMemory_469a {
  strings:
    $key_469a = { 11 e8 [2] 23 ca [2] 25 ff [2] 0b ff [2] 34 e3 }

  condition:
    any of them
}