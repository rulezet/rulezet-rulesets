rule TTP_XOR_WriteProcessMemory_3f19 {
  strings:
    $key_3f19 = { 68 6b [2] 5a 49 [2] 5c 7c [2] 72 7c [2] 4d 60 }

  condition:
    any of them
}