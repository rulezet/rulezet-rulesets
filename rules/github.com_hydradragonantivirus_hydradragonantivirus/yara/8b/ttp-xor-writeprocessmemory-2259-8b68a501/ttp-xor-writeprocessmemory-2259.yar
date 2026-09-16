rule TTP_XOR_WriteProcessMemory_2259 {
  strings:
    $key_2259 = { 75 2b [2] 47 09 [2] 41 3c [2] 6f 3c [2] 50 20 }

  condition:
    any of them
}