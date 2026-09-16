rule TTP_XOR_WriteProcessMemory_fad5 {
  strings:
    $key_fad5 = { ad a7 [2] 9f 85 [2] 99 b0 [2] b7 b0 [2] 88 ac }

  condition:
    any of them
}