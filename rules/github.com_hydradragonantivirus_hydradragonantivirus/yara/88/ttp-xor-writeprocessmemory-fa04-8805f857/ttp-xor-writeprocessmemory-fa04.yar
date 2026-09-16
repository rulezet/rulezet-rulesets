rule TTP_XOR_WriteProcessMemory_fa04 {
  strings:
    $key_fa04 = { ad 76 [2] 9f 54 [2] 99 61 [2] b7 61 [2] 88 7d }

  condition:
    any of them
}