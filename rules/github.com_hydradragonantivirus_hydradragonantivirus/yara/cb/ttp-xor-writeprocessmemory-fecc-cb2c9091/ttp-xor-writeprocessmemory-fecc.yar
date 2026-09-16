rule TTP_XOR_WriteProcessMemory_fecc {
  strings:
    $key_fecc = { a9 be [2] 9b 9c [2] 9d a9 [2] b3 a9 [2] 8c b5 }

  condition:
    any of them
}