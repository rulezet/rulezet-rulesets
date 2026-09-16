rule TTP_XOR_WriteProcessMemory_57fe {
  strings:
    $key_57fe = { 00 8c [2] 32 ae [2] 34 9b [2] 1a 9b [2] 25 87 }

  condition:
    any of them
}