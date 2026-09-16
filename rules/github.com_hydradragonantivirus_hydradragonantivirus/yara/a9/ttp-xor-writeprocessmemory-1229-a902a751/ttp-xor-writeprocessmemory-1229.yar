rule TTP_XOR_WriteProcessMemory_1229 {
  strings:
    $key_1229 = { 45 5b [2] 77 79 [2] 71 4c [2] 5f 4c [2] 60 50 }

  condition:
    any of them
}