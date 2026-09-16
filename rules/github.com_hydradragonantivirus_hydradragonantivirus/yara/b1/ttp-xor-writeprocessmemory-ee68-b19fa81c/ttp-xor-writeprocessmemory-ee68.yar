rule TTP_XOR_WriteProcessMemory_ee68 {
  strings:
    $key_ee68 = { b9 1a [2] 8b 38 [2] 8d 0d [2] a3 0d [2] 9c 11 }

  condition:
    any of them
}