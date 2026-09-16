rule TTP_XOR_WriteProcessMemory_0e38 {
  strings:
    $key_0e38 = { 59 4a [2] 6b 68 [2] 6d 5d [2] 43 5d [2] 7c 41 }

  condition:
    any of them
}