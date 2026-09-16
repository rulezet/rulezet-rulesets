rule TTP_XOR_WriteProcessMemory_124c {
  strings:
    $key_124c = { 45 3e [2] 77 1c [2] 71 29 [2] 5f 29 [2] 60 35 }

  condition:
    any of them
}