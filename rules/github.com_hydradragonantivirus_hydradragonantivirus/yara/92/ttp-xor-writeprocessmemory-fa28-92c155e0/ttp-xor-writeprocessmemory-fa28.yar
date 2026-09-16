rule TTP_XOR_WriteProcessMemory_fa28 {
  strings:
    $key_fa28 = { ad 5a [2] 9f 78 [2] 99 4d [2] b7 4d [2] 88 51 }

  condition:
    any of them
}