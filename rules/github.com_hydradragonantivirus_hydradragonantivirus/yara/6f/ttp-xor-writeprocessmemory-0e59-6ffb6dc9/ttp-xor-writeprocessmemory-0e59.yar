rule TTP_XOR_WriteProcessMemory_0e59 {
  strings:
    $key_0e59 = { 59 2b [2] 6b 09 [2] 6d 3c [2] 43 3c [2] 7c 20 }

  condition:
    any of them
}