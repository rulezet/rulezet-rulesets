rule TTP_XOR_WriteProcessMemory_5a18 {
  strings:
    $key_5a18 = { 0d 6a [2] 3f 48 [2] 39 7d [2] 17 7d [2] 28 61 }

  condition:
    any of them
}