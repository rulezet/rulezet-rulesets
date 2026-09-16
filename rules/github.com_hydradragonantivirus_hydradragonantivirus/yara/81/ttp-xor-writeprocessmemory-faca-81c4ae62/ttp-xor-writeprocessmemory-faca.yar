rule TTP_XOR_WriteProcessMemory_faca {
  strings:
    $key_faca = { ad b8 [2] 9f 9a [2] 99 af [2] b7 af [2] 88 b3 }

  condition:
    any of them
}