rule TTP_XOR_WriteProcessMemory_fbc4 {
  strings:
    $key_fbc4 = { ac b6 [2] 9e 94 [2] 98 a1 [2] b6 a1 [2] 89 bd }

  condition:
    any of them
}