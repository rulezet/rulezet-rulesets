rule TTP_XOR_WriteProcessMemory_59cb {
  strings:
    $key_59cb = { 0e b9 [2] 3c 9b [2] 3a ae [2] 14 ae [2] 2b b2 }

  condition:
    any of them
}