rule TTP_XOR_WriteProcessMemory_e729 {
  strings:
    $key_e729 = { b0 5b [2] 82 79 [2] 84 4c [2] aa 4c [2] 95 50 }

  condition:
    any of them
}