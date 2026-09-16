rule TTP_XOR_WriteProcessMemory_3b28 {
  strings:
    $key_3b28 = { 6c 5a [2] 5e 78 [2] 58 4d [2] 76 4d [2] 49 51 }

  condition:
    any of them
}