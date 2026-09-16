rule TTP_XOR_WriteProcessMemory_eff9 {
  strings:
    $key_eff9 = { b8 8b [2] 8a a9 [2] 8c 9c [2] a2 9c [2] 9d 80 }

  condition:
    any of them
}