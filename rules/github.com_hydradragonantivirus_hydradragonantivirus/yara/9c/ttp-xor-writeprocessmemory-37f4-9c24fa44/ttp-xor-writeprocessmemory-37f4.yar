rule TTP_XOR_WriteProcessMemory_37f4 {
  strings:
    $key_37f4 = { 60 86 [2] 52 a4 [2] 54 91 [2] 7a 91 [2] 45 8d }

  condition:
    any of them
}