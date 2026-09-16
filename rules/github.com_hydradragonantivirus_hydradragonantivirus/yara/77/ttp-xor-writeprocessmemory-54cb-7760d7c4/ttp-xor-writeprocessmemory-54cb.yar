rule TTP_XOR_WriteProcessMemory_54cb {
  strings:
    $key_54cb = { 03 b9 [2] 31 9b [2] 37 ae [2] 19 ae [2] 26 b2 }

  condition:
    any of them
}