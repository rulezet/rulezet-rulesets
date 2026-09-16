rule TTP_XOR_WriteProcessMemory_7569 {
  strings:
    $key_7569 = { 22 1b [2] 10 39 [2] 16 0c [2] 38 0c [2] 07 10 }

  condition:
    any of them
}