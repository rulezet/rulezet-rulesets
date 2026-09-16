rule TTP_XOR_WriteProcessMemory_e2f9 {
  strings:
    $key_e2f9 = { b5 8b [2] 87 a9 [2] 81 9c [2] af 9c [2] 90 80 }

  condition:
    any of them
}