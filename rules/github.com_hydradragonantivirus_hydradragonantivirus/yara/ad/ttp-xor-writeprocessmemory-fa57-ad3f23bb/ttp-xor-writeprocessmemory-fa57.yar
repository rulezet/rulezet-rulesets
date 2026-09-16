rule TTP_XOR_WriteProcessMemory_fa57 {
  strings:
    $key_fa57 = { ad 25 [2] 9f 07 [2] 99 32 [2] b7 32 [2] 88 2e }

  condition:
    any of them
}