rule TTP_XOR_WriteProcessMemory_7ccb {
  strings:
    $key_7ccb = { 2b b9 [2] 19 9b [2] 1f ae [2] 31 ae [2] 0e b2 }

  condition:
    any of them
}