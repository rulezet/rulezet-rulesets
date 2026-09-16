rule TTP_XOR_WriteProcessMemory_63fe {
  strings:
    $key_63fe = { 34 8c [2] 06 ae [2] 00 9b [2] 2e 9b [2] 11 87 }

  condition:
    any of them
}