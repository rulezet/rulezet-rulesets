rule TTP_XOR_WriteProcessMemory_14f3 {
  strings:
    $key_14f3 = { 43 81 [2] 71 a3 [2] 77 96 [2] 59 96 [2] 66 8a }

  condition:
    any of them
}