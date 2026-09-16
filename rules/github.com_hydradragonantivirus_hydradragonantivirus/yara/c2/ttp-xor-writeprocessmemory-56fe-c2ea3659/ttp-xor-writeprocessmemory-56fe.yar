rule TTP_XOR_WriteProcessMemory_56fe {
  strings:
    $key_56fe = { 01 8c [2] 33 ae [2] 35 9b [2] 1b 9b [2] 24 87 }

  condition:
    any of them
}