rule TTP_XOR_WriteProcessMemory_2ccb {
  strings:
    $key_2ccb = { 7b b9 [2] 49 9b [2] 4f ae [2] 61 ae [2] 5e b2 }

  condition:
    any of them
}