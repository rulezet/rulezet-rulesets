rule TTP_XOR_WriteProcessMemory_3359 {
  strings:
    $key_3359 = { 64 2b [2] 56 09 [2] 50 3c [2] 7e 3c [2] 41 20 }

  condition:
    any of them
}