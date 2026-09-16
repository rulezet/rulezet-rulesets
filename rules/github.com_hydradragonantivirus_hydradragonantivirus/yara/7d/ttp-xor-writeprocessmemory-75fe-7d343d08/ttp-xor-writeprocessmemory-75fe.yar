rule TTP_XOR_WriteProcessMemory_75fe {
  strings:
    $key_75fe = { 22 8c [2] 10 ae [2] 16 9b [2] 38 9b [2] 07 87 }

  condition:
    any of them
}