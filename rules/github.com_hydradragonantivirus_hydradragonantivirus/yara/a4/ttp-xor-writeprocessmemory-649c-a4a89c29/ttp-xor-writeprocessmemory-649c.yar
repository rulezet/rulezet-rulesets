rule TTP_XOR_WriteProcessMemory_649c {
  strings:
    $key_649c = { 33 ee [2] 01 cc [2] 07 f9 [2] 29 f9 [2] 16 e5 }

  condition:
    any of them
}