rule TTP_XOR_WriteProcessMemory_928d {
  strings:
    $key_928d = { c5 ff [2] f7 dd [2] f1 e8 [2] df e8 [2] e0 f4 }

  condition:
    any of them
}