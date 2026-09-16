rule TTP_XOR_WriteProcessMemory_7c48 {
  strings:
    $key_7c48 = { 2b 3a [2] 19 18 [2] 1f 2d [2] 31 2d [2] 0e 31 }

  condition:
    any of them
}