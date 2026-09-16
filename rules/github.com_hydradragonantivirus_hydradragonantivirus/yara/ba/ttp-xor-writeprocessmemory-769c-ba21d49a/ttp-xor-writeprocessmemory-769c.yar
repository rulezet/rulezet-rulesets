rule TTP_XOR_WriteProcessMemory_769c {
  strings:
    $key_769c = { 21 ee [2] 13 cc [2] 15 f9 [2] 3b f9 [2] 04 e5 }

  condition:
    any of them
}