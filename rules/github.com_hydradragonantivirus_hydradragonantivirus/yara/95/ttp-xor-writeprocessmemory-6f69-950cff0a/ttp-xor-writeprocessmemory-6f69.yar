rule TTP_XOR_WriteProcessMemory_6f69 {
  strings:
    $key_6f69 = { 38 1b [2] 0a 39 [2] 0c 0c [2] 22 0c [2] 1d 10 }

  condition:
    any of them
}