rule TTP_XOR_WriteProcessMemory_fbc1 {
  strings:
    $key_fbc1 = { ac b3 [2] 9e 91 [2] 98 a4 [2] b6 a4 [2] 89 b8 }

  condition:
    any of them
}