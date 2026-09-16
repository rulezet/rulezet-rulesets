rule TTP_XOR_WriteProcessMemory_e459 {
  strings:
    $key_e459 = { b3 2b [2] 81 09 [2] 87 3c [2] a9 3c [2] 96 20 }

  condition:
    any of them
}