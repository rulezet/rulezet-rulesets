rule TTP_XOR_WriteProcessMemory_42fe {
  strings:
    $key_42fe = { 15 8c [2] 27 ae [2] 21 9b [2] 0f 9b [2] 30 87 }

  condition:
    any of them
}