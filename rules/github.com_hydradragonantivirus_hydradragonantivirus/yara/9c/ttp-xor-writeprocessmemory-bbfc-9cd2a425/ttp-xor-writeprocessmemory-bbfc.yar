rule TTP_XOR_WriteProcessMemory_bbfc {
  strings:
    $key_bbfc = { ec 8e [2] de ac [2] d8 99 [2] f6 99 [2] c9 85 }

  condition:
    any of them
}