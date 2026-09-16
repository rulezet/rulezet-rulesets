rule TTP_XOR_WriteProcessMemory_7c69 {
  strings:
    $key_7c69 = { 2b 1b [2] 19 39 [2] 1f 0c [2] 31 0c [2] 0e 10 }

  condition:
    any of them
}