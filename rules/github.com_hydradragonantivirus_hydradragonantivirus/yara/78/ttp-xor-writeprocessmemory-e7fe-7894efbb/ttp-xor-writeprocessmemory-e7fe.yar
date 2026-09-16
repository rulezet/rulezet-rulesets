rule TTP_XOR_WriteProcessMemory_e7fe {
  strings:
    $key_e7fe = { b0 8c [2] 82 ae [2] 84 9b [2] aa 9b [2] 95 87 }

  condition:
    any of them
}