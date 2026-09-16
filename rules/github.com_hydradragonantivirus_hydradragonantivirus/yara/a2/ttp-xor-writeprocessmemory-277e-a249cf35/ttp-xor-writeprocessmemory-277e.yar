rule TTP_XOR_WriteProcessMemory_277e {
  strings:
    $key_277e = { 70 0c [2] 42 2e [2] 44 1b [2] 6a 1b [2] 55 07 }

  condition:
    any of them
}