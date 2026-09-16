rule TTP_XOR_WriteProcessMemory_8890 {
  strings:
    $key_8890 = { df e2 [2] ed c0 [2] eb f5 [2] c5 f5 [2] fa e9 }

  condition:
    any of them
}