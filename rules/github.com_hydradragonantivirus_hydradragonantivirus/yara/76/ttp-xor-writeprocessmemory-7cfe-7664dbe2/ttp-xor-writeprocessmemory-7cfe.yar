rule TTP_XOR_WriteProcessMemory_7cfe {
  strings:
    $key_7cfe = { 2b 8c [2] 19 ae [2] 1f 9b [2] 31 9b [2] 0e 87 }

  condition:
    any of them
}