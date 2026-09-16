rule TTP_XOR_WriteProcessMemory_4acb {
  strings:
    $key_4acb = { 1d b9 [2] 2f 9b [2] 29 ae [2] 07 ae [2] 38 b2 }

  condition:
    any of them
}