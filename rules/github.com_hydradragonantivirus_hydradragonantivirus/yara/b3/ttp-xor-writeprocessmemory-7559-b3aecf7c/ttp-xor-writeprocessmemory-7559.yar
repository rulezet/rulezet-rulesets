rule TTP_XOR_WriteProcessMemory_7559 {
  strings:
    $key_7559 = { 22 2b [2] 10 09 [2] 16 3c [2] 38 3c [2] 07 20 }

  condition:
    any of them
}