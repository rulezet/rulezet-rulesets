rule TTP_XOR_WriteProcessMemory_029c {
  strings:
    $key_029c = { 55 ee [2] 67 cc [2] 61 f9 [2] 4f f9 [2] 70 e5 }

  condition:
    any of them
}