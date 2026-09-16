rule TTP_XOR_WriteProcessMemory_fa67 {
  strings:
    $key_fa67 = { ad 15 [2] 9f 37 [2] 99 02 [2] b7 02 [2] 88 1e }

  condition:
    any of them
}