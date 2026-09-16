rule TTP_XOR_WriteProcessMemory_fa77 {
  strings:
    $key_fa77 = { ad 05 [2] 9f 27 [2] 99 12 [2] b7 12 [2] 88 0e }

  condition:
    any of them
}