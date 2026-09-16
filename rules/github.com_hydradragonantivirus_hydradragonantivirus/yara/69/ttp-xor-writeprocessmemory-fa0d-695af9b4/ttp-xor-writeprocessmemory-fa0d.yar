rule TTP_XOR_WriteProcessMemory_fa0d {
  strings:
    $key_fa0d = { ad 7f [2] 9f 5d [2] 99 68 [2] b7 68 [2] 88 74 }

  condition:
    any of them
}