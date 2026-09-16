rule TTP_XOR_WriteProcessMemory_faf2 {
  strings:
    $key_faf2 = { ad 80 [2] 9f a2 [2] 99 97 [2] b7 97 [2] 88 8b }

  condition:
    any of them
}