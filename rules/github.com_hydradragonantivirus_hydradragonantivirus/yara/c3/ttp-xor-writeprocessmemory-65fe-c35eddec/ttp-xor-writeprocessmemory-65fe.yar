rule TTP_XOR_WriteProcessMemory_65fe {
  strings:
    $key_65fe = { 32 8c [2] 00 ae [2] 06 9b [2] 28 9b [2] 17 87 }

  condition:
    any of them
}