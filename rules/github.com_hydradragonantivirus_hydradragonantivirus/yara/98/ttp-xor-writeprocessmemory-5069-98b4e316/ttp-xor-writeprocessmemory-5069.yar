rule TTP_XOR_WriteProcessMemory_5069 {
  strings:
    $key_5069 = { 07 1b [2] 35 39 [2] 33 0c [2] 1d 0c [2] 22 10 }

  condition:
    any of them
}