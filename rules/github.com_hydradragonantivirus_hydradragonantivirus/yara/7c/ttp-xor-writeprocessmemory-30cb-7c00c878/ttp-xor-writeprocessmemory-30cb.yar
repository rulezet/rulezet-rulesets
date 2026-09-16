rule TTP_XOR_WriteProcessMemory_30cb {
  strings:
    $key_30cb = { 67 b9 [2] 55 9b [2] 53 ae [2] 7d ae [2] 42 b2 }

  condition:
    any of them
}