rule TTP_XOR_WriteProcessMemory_207e {
  strings:
    $key_207e = { 77 0c [2] 45 2e [2] 43 1b [2] 6d 1b [2] 52 07 }

  condition:
    any of them
}