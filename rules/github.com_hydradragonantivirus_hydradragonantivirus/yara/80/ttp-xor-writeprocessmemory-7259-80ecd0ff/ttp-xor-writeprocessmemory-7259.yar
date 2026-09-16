rule TTP_XOR_WriteProcessMemory_7259 {
  strings:
    $key_7259 = { 25 2b [2] 17 09 [2] 11 3c [2] 3f 3c [2] 00 20 }

  condition:
    any of them
}