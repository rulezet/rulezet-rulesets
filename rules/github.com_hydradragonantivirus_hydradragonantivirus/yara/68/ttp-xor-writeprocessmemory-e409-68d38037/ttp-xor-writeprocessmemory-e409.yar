rule TTP_XOR_WriteProcessMemory_e409 {
  strings:
    $key_e409 = { b3 7b [2] 81 59 [2] 87 6c [2] a9 6c [2] 96 70 }

  condition:
    any of them
}