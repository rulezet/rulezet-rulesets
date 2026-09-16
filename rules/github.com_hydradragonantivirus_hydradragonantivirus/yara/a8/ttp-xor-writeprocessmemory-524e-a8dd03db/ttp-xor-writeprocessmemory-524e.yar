rule TTP_XOR_WriteProcessMemory_524e {
  strings:
    $key_524e = { 05 3c [2] 37 1e [2] 31 2b [2] 1f 2b [2] 20 37 }

  condition:
    any of them
}