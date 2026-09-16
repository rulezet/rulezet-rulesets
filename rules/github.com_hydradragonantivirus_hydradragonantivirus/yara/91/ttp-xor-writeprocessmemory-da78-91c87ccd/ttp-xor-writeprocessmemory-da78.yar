rule TTP_XOR_WriteProcessMemory_da78 {
  strings:
    $key_da78 = { 8d 0a [2] bf 28 [2] b9 1d [2] 97 1d [2] a8 01 }

  condition:
    any of them
}