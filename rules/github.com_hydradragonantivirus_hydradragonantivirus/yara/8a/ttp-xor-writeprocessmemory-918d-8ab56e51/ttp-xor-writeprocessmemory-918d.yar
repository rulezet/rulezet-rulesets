rule TTP_XOR_WriteProcessMemory_918d {
  strings:
    $key_918d = { c6 ff [2] f4 dd [2] f2 e8 [2] dc e8 [2] e3 f4 }

  condition:
    any of them
}