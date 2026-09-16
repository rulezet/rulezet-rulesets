rule TTP_XOR_WriteProcessMemory_f9dd {
  strings:
    $key_f9dd = { ae af [2] 9c 8d [2] 9a b8 [2] b4 b8 [2] 8b a4 }

  condition:
    any of them
}