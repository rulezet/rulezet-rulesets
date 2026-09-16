rule TTP_XOR_WriteProcessMemory_76fe {
  strings:
    $key_76fe = { 21 8c [2] 13 ae [2] 15 9b [2] 3b 9b [2] 04 87 }

  condition:
    any of them
}