rule TTP_XOR_WriteProcessMemory_bb4b {
  strings:
    $key_bb4b = { ec 39 [2] de 1b [2] d8 2e [2] f6 2e [2] c9 32 }

  condition:
    any of them
}