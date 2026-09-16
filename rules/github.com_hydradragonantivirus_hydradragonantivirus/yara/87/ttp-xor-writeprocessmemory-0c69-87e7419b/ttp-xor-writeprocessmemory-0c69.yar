rule TTP_XOR_WriteProcessMemory_0c69 {
  strings:
    $key_0c69 = { 5b 1b [2] 69 39 [2] 6f 0c [2] 41 0c [2] 7e 10 }

  condition:
    any of them
}