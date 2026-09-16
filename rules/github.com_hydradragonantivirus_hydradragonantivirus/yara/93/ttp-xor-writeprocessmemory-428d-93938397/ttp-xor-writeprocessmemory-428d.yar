rule TTP_XOR_WriteProcessMemory_428d {
  strings:
    $key_428d = { 15 ff [2] 27 dd [2] 21 e8 [2] 0f e8 [2] 30 f4 }

  condition:
    any of them
}