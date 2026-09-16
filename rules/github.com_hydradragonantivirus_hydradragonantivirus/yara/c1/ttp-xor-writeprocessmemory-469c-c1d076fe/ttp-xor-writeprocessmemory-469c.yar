rule TTP_XOR_WriteProcessMemory_469c {
  strings:
    $key_469c = { 11 ee [2] 23 cc [2] 25 f9 [2] 0b f9 [2] 34 e5 }

  condition:
    any of them
}