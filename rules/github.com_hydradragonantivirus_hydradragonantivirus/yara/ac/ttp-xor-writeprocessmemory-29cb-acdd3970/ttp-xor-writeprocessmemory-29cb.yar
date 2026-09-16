rule TTP_XOR_WriteProcessMemory_29cb {
  strings:
    $key_29cb = { 7e b9 [2] 4c 9b [2] 4a ae [2] 64 ae [2] 5b b2 }

  condition:
    any of them
}