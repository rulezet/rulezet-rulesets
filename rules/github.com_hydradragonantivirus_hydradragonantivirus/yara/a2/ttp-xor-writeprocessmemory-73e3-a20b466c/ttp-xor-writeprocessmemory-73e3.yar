rule TTP_XOR_WriteProcessMemory_73e3 {
  strings:
    $key_73e3 = { 24 91 [2] 16 b3 [2] 10 86 [2] 3e 86 [2] 01 9a }

  condition:
    any of them
}