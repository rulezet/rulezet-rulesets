rule TTP_XOR_WriteProcessMemory_37a4 {
  strings:
    $key_37a4 = { 60 d6 [2] 52 f4 [2] 54 c1 [2] 7a c1 [2] 45 dd }

  condition:
    any of them
}