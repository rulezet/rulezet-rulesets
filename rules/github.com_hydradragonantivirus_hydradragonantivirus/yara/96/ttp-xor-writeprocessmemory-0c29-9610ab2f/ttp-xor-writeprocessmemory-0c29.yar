rule TTP_XOR_WriteProcessMemory_0c29 {
  strings:
    $key_0c29 = { 5b 5b [2] 69 79 [2] 6f 4c [2] 41 4c [2] 7e 50 }

  condition:
    any of them
}