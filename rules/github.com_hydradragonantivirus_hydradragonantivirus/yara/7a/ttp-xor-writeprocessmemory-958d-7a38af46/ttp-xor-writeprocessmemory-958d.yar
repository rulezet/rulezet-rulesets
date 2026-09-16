rule TTP_XOR_WriteProcessMemory_958d {
  strings:
    $key_958d = { c2 ff [2] f0 dd [2] f6 e8 [2] d8 e8 [2] e7 f4 }

  condition:
    any of them
}