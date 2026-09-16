rule TTP_XOR_WriteProcessMemory_2a69 {
  strings:
    $key_2a69 = { 7d 1b [2] 4f 39 [2] 49 0c [2] 67 0c [2] 58 10 }

  condition:
    any of them
}