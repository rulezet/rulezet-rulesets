rule TTP_XOR_WriteProcessMemory_17cb {
  strings:
    $key_17cb = { 40 b9 [2] 72 9b [2] 74 ae [2] 5a ae [2] 65 b2 }

  condition:
    any of them
}