rule TTP_XOR_WriteProcessMemory_fbcb {
  strings:
    $key_fbcb = { ac b9 [2] 9e 9b [2] 98 ae [2] b6 ae [2] 89 b2 }

  condition:
    any of them
}