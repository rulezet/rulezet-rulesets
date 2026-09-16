rule TTP_XOR_WriteProcessMemory_d7cb {
  strings:
    $key_d7cb = { 80 b9 [2] b2 9b [2] b4 ae [2] 9a ae [2] a5 b2 }

  condition:
    any of them
}