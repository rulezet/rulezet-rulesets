rule TTP_XOR_WriteProcessMemory_122c {
  strings:
    $key_122c = { 45 5e [2] 77 7c [2] 71 49 [2] 5f 49 [2] 60 55 }

  condition:
    any of them
}