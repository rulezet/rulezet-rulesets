rule TTP_XOR_WriteProcessMemory_fad4 {
  strings:
    $key_fad4 = { ad a6 [2] 9f 84 [2] 99 b1 [2] b7 b1 [2] 88 ad }

  condition:
    any of them
}