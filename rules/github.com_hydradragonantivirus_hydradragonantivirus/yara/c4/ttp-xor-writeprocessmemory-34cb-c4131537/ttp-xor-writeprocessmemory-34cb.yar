rule TTP_XOR_WriteProcessMemory_34cb {
  strings:
    $key_34cb = { 63 b9 [2] 51 9b [2] 57 ae [2] 79 ae [2] 46 b2 }

  condition:
    any of them
}