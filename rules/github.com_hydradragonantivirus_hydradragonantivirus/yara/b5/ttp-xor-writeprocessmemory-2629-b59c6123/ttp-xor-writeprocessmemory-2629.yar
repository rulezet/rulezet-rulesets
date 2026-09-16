rule TTP_XOR_WriteProcessMemory_2629 {
  strings:
    $key_2629 = { 71 5b [2] 43 79 [2] 45 4c [2] 6b 4c [2] 54 50 }

  condition:
    any of them
}