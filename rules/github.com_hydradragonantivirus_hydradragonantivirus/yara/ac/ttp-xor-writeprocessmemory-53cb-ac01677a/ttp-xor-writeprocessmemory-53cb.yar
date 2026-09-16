rule TTP_XOR_WriteProcessMemory_53cb {
  strings:
    $key_53cb = { 04 b9 [2] 36 9b [2] 30 ae [2] 1e ae [2] 21 b2 }

  condition:
    any of them
}