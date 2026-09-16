rule TTP_XOR_WriteProcessMemory_d2cb {
  strings:
    $key_d2cb = { 85 b9 [2] b7 9b [2] b1 ae [2] 9f ae [2] a0 b2 }

  condition:
    any of them
}