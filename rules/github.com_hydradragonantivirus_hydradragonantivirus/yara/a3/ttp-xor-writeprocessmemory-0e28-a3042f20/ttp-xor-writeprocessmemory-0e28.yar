rule TTP_XOR_WriteProcessMemory_0e28 {
  strings:
    $key_0e28 = { 59 5a [2] 6b 78 [2] 6d 4d [2] 43 4d [2] 7c 51 }

  condition:
    any of them
}