rule TTP_XOR_WriteProcessMemory_32cb {
  strings:
    $key_32cb = { 65 b9 [2] 57 9b [2] 51 ae [2] 7f ae [2] 40 b2 }

  condition:
    any of them
}