rule TTP_XOR_WriteProcessMemory_72fe {
  strings:
    $key_72fe = { 25 8c [2] 17 ae [2] 11 9b [2] 3f 9b [2] 00 87 }

  condition:
    any of them
}