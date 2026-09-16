rule TTP_XOR_WriteProcessMemory_10fe {
  strings:
    $key_10fe = { 47 8c [2] 75 ae [2] 73 9b [2] 5d 9b [2] 62 87 }

  condition:
    any of them
}