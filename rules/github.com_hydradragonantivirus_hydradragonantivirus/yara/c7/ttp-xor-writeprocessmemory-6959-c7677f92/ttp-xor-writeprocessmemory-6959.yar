rule TTP_XOR_WriteProcessMemory_6959 {
  strings:
    $key_6959 = { 3e 2b [2] 0c 09 [2] 0a 3c [2] 24 3c [2] 1b 20 }

  condition:
    any of them
}