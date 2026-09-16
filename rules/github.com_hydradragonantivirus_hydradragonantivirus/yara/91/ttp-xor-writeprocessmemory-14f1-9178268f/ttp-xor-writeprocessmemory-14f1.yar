rule TTP_XOR_WriteProcessMemory_14f1 {
  strings:
    $key_14f1 = { 43 83 [2] 71 a1 [2] 77 94 [2] 59 94 [2] 66 88 }

  condition:
    any of them
}