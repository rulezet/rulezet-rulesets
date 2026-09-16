rule TTP_XOR_WriteProcessMemory_95fe {
  strings:
    $key_95fe = { c2 8c [2] f0 ae [2] f6 9b [2] d8 9b [2] e7 87 }

  condition:
    any of them
}