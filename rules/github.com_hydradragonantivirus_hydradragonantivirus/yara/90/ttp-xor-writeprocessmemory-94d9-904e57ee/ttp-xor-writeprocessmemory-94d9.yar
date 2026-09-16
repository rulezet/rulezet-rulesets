rule TTP_XOR_WriteProcessMemory_94d9 {
  strings:
    $key_94d9 = { c3 ab [2] f1 89 [2] f7 bc [2] d9 bc [2] e6 a0 }

  condition:
    any of them
}