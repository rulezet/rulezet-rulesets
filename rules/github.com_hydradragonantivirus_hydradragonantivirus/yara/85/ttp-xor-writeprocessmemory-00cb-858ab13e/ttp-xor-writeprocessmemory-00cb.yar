rule TTP_XOR_WriteProcessMemory_00cb {
  strings:
    $key_00cb = { 57 b9 [2] 65 9b [2] 63 ae [2] 4d ae [2] 72 b2 }

  condition:
    any of them
}