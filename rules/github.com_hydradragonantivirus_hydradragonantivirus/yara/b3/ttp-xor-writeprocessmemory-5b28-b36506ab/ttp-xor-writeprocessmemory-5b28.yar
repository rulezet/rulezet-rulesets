rule TTP_XOR_WriteProcessMemory_5b28 {
  strings:
    $key_5b28 = { 0c 5a [2] 3e 78 [2] 38 4d [2] 16 4d [2] 29 51 }

  condition:
    any of them
}