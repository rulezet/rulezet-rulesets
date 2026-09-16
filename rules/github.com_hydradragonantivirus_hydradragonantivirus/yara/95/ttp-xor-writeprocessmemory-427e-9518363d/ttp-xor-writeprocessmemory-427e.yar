rule TTP_XOR_WriteProcessMemory_427e {
  strings:
    $key_427e = { 15 0c [2] 27 2e [2] 21 1b [2] 0f 1b [2] 30 07 }

  condition:
    any of them
}