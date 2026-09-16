rule TTP_XOR_WriteProcessMemory_577e {
  strings:
    $key_577e = { 00 0c [2] 32 2e [2] 34 1b [2] 1a 1b [2] 25 07 }

  condition:
    any of them
}