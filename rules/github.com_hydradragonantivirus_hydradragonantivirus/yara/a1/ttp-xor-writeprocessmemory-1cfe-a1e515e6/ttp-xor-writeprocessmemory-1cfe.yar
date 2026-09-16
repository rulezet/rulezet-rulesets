rule TTP_XOR_WriteProcessMemory_1cfe {
  strings:
    $key_1cfe = { 4b 8c [2] 79 ae [2] 7f 9b [2] 51 9b [2] 6e 87 }

  condition:
    any of them
}