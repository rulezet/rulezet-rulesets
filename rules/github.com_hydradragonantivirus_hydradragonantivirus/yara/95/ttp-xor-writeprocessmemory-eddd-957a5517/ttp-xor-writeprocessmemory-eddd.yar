rule TTP_XOR_WriteProcessMemory_eddd {
  strings:
    $key_eddd = { ba af [2] 88 8d [2] 8e b8 [2] a0 b8 [2] 9f a4 }

  condition:
    any of them
}