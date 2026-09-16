rule TTP_XOR_WriteProcessMemory_03fe {
  strings:
    $key_03fe = { 54 8c [2] 66 ae [2] 60 9b [2] 4e 9b [2] 71 87 }

  condition:
    any of them
}