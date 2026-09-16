rule TTP_XOR_WriteProcessMemory_878d {
  strings:
    $key_878d = { d0 ff [2] e2 dd [2] e4 e8 [2] ca e8 [2] f5 f4 }

  condition:
    any of them
}