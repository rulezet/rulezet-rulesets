rule TTP_XOR_WriteProcessMemory_17fe {
  strings:
    $key_17fe = { 40 8c [2] 72 ae [2] 74 9b [2] 5a 9b [2] 65 87 }

  condition:
    any of them
}