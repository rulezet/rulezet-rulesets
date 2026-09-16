rule TTP_XOR_WriteProcessMemory_0e19 {
  strings:
    $key_0e19 = { 59 6b [2] 6b 49 [2] 6d 7c [2] 43 7c [2] 7c 60 }

  condition:
    any of them
}