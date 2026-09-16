rule TTP_XOR_WriteProcessMemory_24cb {
  strings:
    $key_24cb = { 73 b9 [2] 41 9b [2] 47 ae [2] 69 ae [2] 56 b2 }

  condition:
    any of them
}