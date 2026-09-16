rule TTP_XOR_WriteProcessMemory_facd {
  strings:
    $key_facd = { ad bf [2] 9f 9d [2] 99 a8 [2] b7 a8 [2] 88 b4 }

  condition:
    any of them
}