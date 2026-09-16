rule TTP_XOR_WriteProcessMemory_7d7e {
  strings:
    $key_7d7e = { 2a 0c [2] 18 2e [2] 1e 1b [2] 30 1b [2] 0f 07 }

  condition:
    any of them
}