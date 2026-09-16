rule TTP_XOR_WriteProcessMemory_61fe {
  strings:
    $key_61fe = { 36 8c [2] 04 ae [2] 02 9b [2] 2c 9b [2] 13 87 }

  condition:
    any of them
}