rule TTP_XOR_WriteProcessMemory_1e28 {
  strings:
    $key_1e28 = { 49 5a [2] 7b 78 [2] 7d 4d [2] 53 4d [2] 6c 51 }

  condition:
    any of them
}