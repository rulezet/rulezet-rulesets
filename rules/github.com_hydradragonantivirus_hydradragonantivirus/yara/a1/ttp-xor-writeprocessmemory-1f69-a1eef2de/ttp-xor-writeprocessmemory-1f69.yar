rule TTP_XOR_WriteProcessMemory_1f69 {
  strings:
    $key_1f69 = { 48 1b [2] 7a 39 [2] 7c 0c [2] 52 0c [2] 6d 10 }

  condition:
    any of them
}