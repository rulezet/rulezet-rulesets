rule TTP_XOR_WriteProcessMemory_fdcc {
  strings:
    $key_fdcc = { aa be [2] 98 9c [2] 9e a9 [2] b0 a9 [2] 8f b5 }

  condition:
    any of them
}