rule TTP_XOR_WriteProcessMemory_6929 {
  strings:
    $key_6929 = { 3e 5b [2] 0c 79 [2] 0a 4c [2] 24 4c [2] 1b 50 }

  condition:
    any of them
}