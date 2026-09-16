rule TTP_XOR_WriteProcessMemory_b9fb {
  strings:
    $key_b9fb = { ee 89 [2] dc ab [2] da 9e [2] f4 9e [2] cb 82 }

  condition:
    any of them
}