rule TTP_XOR_WriteProcessMemory_14f9 {
  strings:
    $key_14f9 = { 43 8b [2] 71 a9 [2] 77 9c [2] 59 9c [2] 66 80 }

  condition:
    any of them
}