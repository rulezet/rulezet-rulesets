rule TTP_XOR_WriteProcessMemory_7369 {
  strings:
    $key_7369 = { 24 1b [2] 16 39 [2] 10 0c [2] 3e 0c [2] 01 10 }

  condition:
    any of them
}