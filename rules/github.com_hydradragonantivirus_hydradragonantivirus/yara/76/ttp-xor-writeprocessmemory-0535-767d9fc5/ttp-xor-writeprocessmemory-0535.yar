rule TTP_XOR_WriteProcessMemory_0535 {
  strings:
    $key_0535 = { 52 47 [2] 60 65 [2] 66 50 [2] 48 50 [2] 77 4c }

  condition:
    any of them
}