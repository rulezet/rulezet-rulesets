rule TTP_XOR_WriteProcessMemory_127e {
  strings:
    $key_127e = { 45 0c [2] 77 2e [2] 71 1b [2] 5f 1b [2] 60 07 }

  condition:
    any of them
}