rule TTP_XOR_WriteProcessMemory_2469 {
  strings:
    $key_2469 = { 73 1b [2] 41 39 [2] 47 0c [2] 69 0c [2] 56 10 }

  condition:
    any of them
}