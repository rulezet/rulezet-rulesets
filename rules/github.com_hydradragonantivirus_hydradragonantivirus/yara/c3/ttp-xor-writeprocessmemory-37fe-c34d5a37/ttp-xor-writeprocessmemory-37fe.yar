rule TTP_XOR_WriteProcessMemory_37fe {
  strings:
    $key_37fe = { 60 8c [2] 52 ae [2] 54 9b [2] 7a 9b [2] 45 87 }

  condition:
    any of them
}