rule TTP_XOR_WriteProcessMemory_3469 {
  strings:
    $key_3469 = { 63 1b [2] 51 39 [2] 57 0c [2] 79 0c [2] 46 10 }

  condition:
    any of them
}