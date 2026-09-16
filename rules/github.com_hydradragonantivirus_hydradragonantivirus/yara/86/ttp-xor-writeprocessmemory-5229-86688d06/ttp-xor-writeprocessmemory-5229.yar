rule TTP_XOR_WriteProcessMemory_5229 {
  strings:
    $key_5229 = { 05 5b [2] 37 79 [2] 31 4c [2] 1f 4c [2] 20 50 }

  condition:
    any of them
}