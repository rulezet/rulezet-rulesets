rule TTP_XOR_WriteProcessMemory_66fe {
  strings:
    $key_66fe = { 31 8c [2] 03 ae [2] 05 9b [2] 2b 9b [2] 14 87 }

  condition:
    any of them
}