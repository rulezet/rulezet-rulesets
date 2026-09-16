rule TTP_XOR_WriteProcessMemory_6939 {
  strings:
    $key_6939 = { 3e 4b [2] 0c 69 [2] 0a 5c [2] 24 5c [2] 1b 40 }

  condition:
    any of them
}