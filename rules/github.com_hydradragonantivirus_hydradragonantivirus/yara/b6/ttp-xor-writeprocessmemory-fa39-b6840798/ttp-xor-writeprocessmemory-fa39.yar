rule TTP_XOR_WriteProcessMemory_fa39 {
  strings:
    $key_fa39 = { ad 4b [2] 9f 69 [2] 99 5c [2] b7 5c [2] 88 40 }

  condition:
    any of them
}