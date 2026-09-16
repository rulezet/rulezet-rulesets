rule TTP_XOR_WriteProcessMemory_79cb {
  strings:
    $key_79cb = { 2e b9 [2] 1c 9b [2] 1a ae [2] 34 ae [2] 0b b2 }

  condition:
    any of them
}