rule TTP_XOR_WriteProcessMemory_11fe {
  strings:
    $key_11fe = { 46 8c [2] 74 ae [2] 72 9b [2] 5c 9b [2] 63 87 }

  condition:
    any of them
}