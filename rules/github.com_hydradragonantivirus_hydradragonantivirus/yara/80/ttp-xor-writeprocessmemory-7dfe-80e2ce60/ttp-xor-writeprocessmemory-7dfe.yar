rule TTP_XOR_WriteProcessMemory_7dfe {
  strings:
    $key_7dfe = { 2a 8c [2] 18 ae [2] 1e 9b [2] 30 9b [2] 0f 87 }

  condition:
    any of them
}