rule TTP_XOR_WriteProcessMemory_ebd5 {
  strings:
    $key_ebd5 = { bc a7 [2] 8e 85 [2] 88 b0 [2] a6 b0 [2] 99 ac }

  condition:
    any of them
}