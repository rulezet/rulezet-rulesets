rule TTP_XOR_WriteProcessMemory_cbdd {
  strings:
    $key_cbdd = { 9c af [2] ae 8d [2] a8 b8 [2] 86 b8 [2] b9 a4 }

  condition:
    any of them
}