rule TTP_XOR_WriteProcessMemory_697e {
  strings:
    $key_697e = { 3e 0c [2] 0c 2e [2] 0a 1b [2] 24 1b [2] 1b 07 }

  condition:
    any of them
}