rule TTP_XOR_WriteProcessMemory_409c {
  strings:
    $key_409c = { 17 ee [2] 25 cc [2] 23 f9 [2] 0d f9 [2] 32 e5 }

  condition:
    any of them
}