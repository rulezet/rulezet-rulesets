rule TTP_XOR_WriteProcessMemory_44fe {
  strings:
    $key_44fe = { 13 8c [2] 21 ae [2] 27 9b [2] 09 9b [2] 36 87 }

  condition:
    any of them
}