rule TTP_XOR_WriteProcessMemory_2bb0 {
  strings:
    $key_2bb0 = { 7c c2 [2] 4e e0 [2] 48 d5 [2] 66 d5 [2] 59 c9 }

  condition:
    any of them
}