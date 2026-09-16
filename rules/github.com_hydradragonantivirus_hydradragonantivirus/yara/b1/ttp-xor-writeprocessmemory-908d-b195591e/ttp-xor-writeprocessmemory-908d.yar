rule TTP_XOR_WriteProcessMemory_908d {
  strings:
    $key_908d = { c7 ff [2] f5 dd [2] f3 e8 [2] dd e8 [2] e2 f4 }

  condition:
    any of them
}