rule TTP_XOR_WriteProcessMemory_1f19 {
  strings:
    $key_1f19 = { 48 6b [2] 7a 49 [2] 7c 7c [2] 52 7c [2] 6d 60 }

  condition:
    any of them
}