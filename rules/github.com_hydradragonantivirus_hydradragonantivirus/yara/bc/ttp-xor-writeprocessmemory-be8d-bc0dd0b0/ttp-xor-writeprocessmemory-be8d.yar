rule TTP_XOR_WriteProcessMemory_be8d {
  strings:
    $key_be8d = { e9 ff [2] db dd [2] dd e8 [2] f3 e8 [2] cc f4 }

  condition:
    any of them
}