rule TTP_XOR_WriteProcessMemory_0978 {
  strings:
    $key_0978 = { 5e 0a [2] 6c 28 [2] 6a 1d [2] 44 1d [2] 7b 01 }

  condition:
    any of them
}