rule TTP_XOR_WriteProcessMemory_93fe {
  strings:
    $key_93fe = { c4 8c [2] f6 ae [2] f0 9b [2] de 9b [2] e1 87 }

  condition:
    any of them
}