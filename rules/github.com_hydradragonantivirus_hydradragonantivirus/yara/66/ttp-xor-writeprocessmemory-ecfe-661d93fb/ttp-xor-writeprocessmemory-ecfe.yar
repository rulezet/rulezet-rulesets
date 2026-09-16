rule TTP_XOR_WriteProcessMemory_ecfe {
  strings:
    $key_ecfe = { bb 8c [2] 89 ae [2] 8f 9b [2] a1 9b [2] 9e 87 }

  condition:
    any of them
}