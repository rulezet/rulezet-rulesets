rule TTP_XOR_WriteProcessMemory_8093 {
  strings:
    $key_8093 = { d7 e1 [2] e5 c3 [2] e3 f6 [2] cd f6 [2] f2 ea }

  condition:
    any of them
}