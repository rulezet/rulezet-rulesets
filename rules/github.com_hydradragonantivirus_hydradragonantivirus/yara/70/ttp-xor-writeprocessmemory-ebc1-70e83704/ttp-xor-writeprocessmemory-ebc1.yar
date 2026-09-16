rule TTP_XOR_WriteProcessMemory_ebc1 {
  strings:
    $key_ebc1 = { bc b3 [2] 8e 91 [2] 88 a4 [2] a6 a4 [2] 99 b8 }

  condition:
    any of them
}