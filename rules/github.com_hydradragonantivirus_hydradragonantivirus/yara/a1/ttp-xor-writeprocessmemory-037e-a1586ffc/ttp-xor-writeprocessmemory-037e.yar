rule TTP_XOR_WriteProcessMemory_037e {
  strings:
    $key_037e = { 54 0c [2] 66 2e [2] 60 1b [2] 4e 1b [2] 71 07 }

  condition:
    any of them
}