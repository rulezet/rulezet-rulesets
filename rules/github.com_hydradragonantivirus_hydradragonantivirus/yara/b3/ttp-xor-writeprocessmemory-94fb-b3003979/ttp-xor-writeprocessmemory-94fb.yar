rule TTP_XOR_WriteProcessMemory_94fb {
  strings:
    $key_94fb = { c3 89 [2] f1 ab [2] f7 9e [2] d9 9e [2] e6 82 }

  condition:
    any of them
}