rule TTP_XOR_WriteProcessMemory_85fe {
  strings:
    $key_85fe = { d2 8c [2] e0 ae [2] e6 9b [2] c8 9b [2] f7 87 }

  condition:
    any of them
}