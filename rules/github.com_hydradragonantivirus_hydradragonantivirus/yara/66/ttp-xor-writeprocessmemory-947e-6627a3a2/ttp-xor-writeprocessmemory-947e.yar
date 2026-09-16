rule TTP_XOR_WriteProcessMemory_947e {
  strings:
    $key_947e = { c3 0c [2] f1 2e [2] f7 1b [2] d9 1b [2] e6 07 }

  condition:
    any of them
}