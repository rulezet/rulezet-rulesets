rule TTP_XOR_WriteProcessMemory_6909 {
  strings:
    $key_6909 = { 3e 7b [2] 0c 59 [2] 0a 6c [2] 24 6c [2] 1b 70 }

  condition:
    any of them
}