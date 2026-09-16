rule TTP_XOR_WriteProcessMemory_8086 {
  strings:
    $key_8086 = { d7 f4 [2] e5 d6 [2] e3 e3 [2] cd e3 [2] f2 ff }

  condition:
    any of them
}