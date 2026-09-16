rule TTP_XOR_WriteProcessMemory_fad6 {
  strings:
    $key_fad6 = { ad a4 [2] 9f 86 [2] 99 b3 [2] b7 b3 [2] 88 af }

  condition:
    any of them
}