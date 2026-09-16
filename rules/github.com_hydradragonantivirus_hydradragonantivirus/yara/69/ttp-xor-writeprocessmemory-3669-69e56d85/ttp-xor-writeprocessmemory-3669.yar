rule TTP_XOR_WriteProcessMemory_3669 {
  strings:
    $key_3669 = { 61 1b [2] 53 39 [2] 55 0c [2] 7b 0c [2] 44 10 }

  condition:
    any of them
}