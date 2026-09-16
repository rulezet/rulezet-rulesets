rule TTP_XOR_WriteProcessMemory_e469 {
  strings:
    $key_e469 = { b3 1b [2] 81 39 [2] 87 0c [2] a9 0c [2] 96 10 }

  condition:
    any of them
}