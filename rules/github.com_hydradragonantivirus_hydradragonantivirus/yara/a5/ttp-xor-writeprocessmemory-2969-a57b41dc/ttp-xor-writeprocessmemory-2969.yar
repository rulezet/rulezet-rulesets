rule TTP_XOR_WriteProcessMemory_2969 {
  strings:
    $key_2969 = { 7e 1b [2] 4c 39 [2] 4a 0c [2] 64 0c [2] 5b 10 }

  condition:
    any of them
}