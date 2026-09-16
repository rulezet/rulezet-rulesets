rule TTP_XOR_WriteProcessMemory_7b28 {
  strings:
    $key_7b28 = { 2c 5a [2] 1e 78 [2] 18 4d [2] 36 4d [2] 09 51 }

  condition:
    any of them
}