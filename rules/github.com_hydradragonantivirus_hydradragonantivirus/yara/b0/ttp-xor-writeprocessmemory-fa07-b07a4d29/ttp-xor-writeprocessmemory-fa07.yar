rule TTP_XOR_WriteProcessMemory_fa07 {
  strings:
    $key_fa07 = { ad 75 [2] 9f 57 [2] 99 62 [2] b7 62 [2] 88 7e }

  condition:
    any of them
}