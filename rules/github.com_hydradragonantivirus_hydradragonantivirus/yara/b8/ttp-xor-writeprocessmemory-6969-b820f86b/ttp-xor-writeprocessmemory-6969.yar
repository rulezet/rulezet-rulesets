rule TTP_XOR_WriteProcessMemory_6969 {
  strings:
    $key_6969 = { 3e 1b [2] 0c 39 [2] 0a 0c [2] 24 0c [2] 1b 10 }

  condition:
    any of them
}