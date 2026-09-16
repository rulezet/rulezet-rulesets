rule TTP_XOR_WriteProcessMemory_52fe {
  strings:
    $key_52fe = { 05 8c [2] 37 ae [2] 31 9b [2] 1f 9b [2] 20 87 }

  condition:
    any of them
}