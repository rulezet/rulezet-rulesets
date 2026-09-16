rule TTP_XOR_WriteProcessMemory_8083 {
  strings:
    $key_8083 = { d7 f1 [2] e5 d3 [2] e3 e6 [2] cd e6 [2] f2 fa }

  condition:
    any of them
}