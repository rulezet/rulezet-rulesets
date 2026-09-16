rule TTP_XOR_WriteProcessMemory_139c {
  strings:
    $key_139c = { 44 ee [2] 76 cc [2] 70 f9 [2] 5e f9 [2] 61 e5 }

  condition:
    any of them
}