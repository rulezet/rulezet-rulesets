rule TTP_XOR_WriteProcessMemory_80e3 {
  strings:
    $key_80e3 = { d7 91 [2] e5 b3 [2] e3 86 [2] cd 86 [2] f2 9a }

  condition:
    any of them
}