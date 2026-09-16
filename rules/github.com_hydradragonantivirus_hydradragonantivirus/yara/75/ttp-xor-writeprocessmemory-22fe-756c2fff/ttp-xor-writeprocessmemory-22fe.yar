rule TTP_XOR_WriteProcessMemory_22fe {
  strings:
    $key_22fe = { 75 8c [2] 47 ae [2] 41 9b [2] 6f 9b [2] 50 87 }

  condition:
    any of them
}