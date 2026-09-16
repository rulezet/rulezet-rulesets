rule TTP_XOR_WriteProcessMemory_4ccb {
  strings:
    $key_4ccb = { 1b b9 [2] 29 9b [2] 2f ae [2] 01 ae [2] 3e b2 }

  condition:
    any of them
}