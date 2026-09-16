rule TTP_XOR_WriteProcessMemory_4cfe {
  strings:
    $key_4cfe = { 1b 8c [2] 29 ae [2] 2f 9b [2] 01 9b [2] 3e 87 }

  condition:
    any of them
}