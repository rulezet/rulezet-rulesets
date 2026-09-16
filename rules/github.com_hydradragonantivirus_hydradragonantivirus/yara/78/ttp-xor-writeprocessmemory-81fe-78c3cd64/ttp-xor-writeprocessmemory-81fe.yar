rule TTP_XOR_WriteProcessMemory_81fe {
  strings:
    $key_81fe = { d6 8c [2] e4 ae [2] e2 9b [2] cc 9b [2] f3 87 }

  condition:
    any of them
}