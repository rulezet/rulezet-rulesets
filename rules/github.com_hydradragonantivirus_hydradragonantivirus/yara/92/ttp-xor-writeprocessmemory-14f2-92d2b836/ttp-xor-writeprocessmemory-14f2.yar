rule TTP_XOR_WriteProcessMemory_14f2 {
  strings:
    $key_14f2 = { 43 80 [2] 71 a2 [2] 77 97 [2] 59 97 [2] 66 8b }

  condition:
    any of them
}