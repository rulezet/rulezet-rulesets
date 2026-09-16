rule TTP_XOR_WriteProcessMemory_fa86 {
  strings:
    $key_fa86 = { ad f4 [2] 9f d6 [2] 99 e3 [2] b7 e3 [2] 88 ff }

  condition:
    any of them
}