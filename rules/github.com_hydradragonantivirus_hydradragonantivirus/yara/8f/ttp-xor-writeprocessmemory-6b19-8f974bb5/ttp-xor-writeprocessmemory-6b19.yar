rule TTP_XOR_WriteProcessMemory_6b19 {
  strings:
    $key_6b19 = { 3c 6b [2] 0e 49 [2] 08 7c [2] 26 7c [2] 19 60 }

  condition:
    any of them
}