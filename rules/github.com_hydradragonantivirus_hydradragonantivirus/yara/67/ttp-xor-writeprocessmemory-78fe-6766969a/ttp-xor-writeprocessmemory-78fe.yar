rule TTP_XOR_WriteProcessMemory_78fe {
  strings:
    $key_78fe = { 2f 8c [2] 1d ae [2] 1b 9b [2] 35 9b [2] 0a 87 }

  condition:
    any of them
}