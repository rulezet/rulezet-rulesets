rule TTP_XOR_WriteProcessMemory_fadc {
  strings:
    $key_fadc = { ad ae [2] 9f 8c [2] 99 b9 [2] b7 b9 [2] 88 a5 }

  condition:
    any of them
}