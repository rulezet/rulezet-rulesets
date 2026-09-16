rule TTP_XOR_WriteProcessMemory_4328 {
  strings:
    $key_4328 = { 14 5a [2] 26 78 [2] 20 4d [2] 0e 4d [2] 31 51 }

  condition:
    any of them
}