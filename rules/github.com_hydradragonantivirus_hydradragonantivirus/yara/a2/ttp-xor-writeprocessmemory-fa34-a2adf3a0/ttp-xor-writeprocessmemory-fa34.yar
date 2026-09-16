rule TTP_XOR_WriteProcessMemory_fa34 {
  strings:
    $key_fa34 = { ad 46 [2] 9f 64 [2] 99 51 [2] b7 51 [2] 88 4d }

  condition:
    any of them
}