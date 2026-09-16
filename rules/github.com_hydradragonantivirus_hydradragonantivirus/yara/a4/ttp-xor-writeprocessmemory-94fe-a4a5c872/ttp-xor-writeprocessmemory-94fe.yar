rule TTP_XOR_WriteProcessMemory_94fe {
  strings:
    $key_94fe = { c3 8c [2] f1 ae [2] f7 9b [2] d9 9b [2] e6 87 }

  condition:
    any of them
}