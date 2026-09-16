rule TTP_XOR_WriteProcessMemory_ebc0 {
  strings:
    $key_ebc0 = { bc b2 [2] 8e 90 [2] 88 a5 [2] a6 a5 [2] 99 b9 }

  condition:
    any of them
}