rule TTP_XOR_WriteProcessMemory_fa23 {
  strings:
    $key_fa23 = { ad 51 [2] 9f 73 [2] 99 46 [2] b7 46 [2] 88 5a }

  condition:
    any of them
}