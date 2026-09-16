rule TTP_XOR_WriteProcessMemory_2408 {
  strings:
    $key_2408 = { 73 7a [2] 41 58 [2] 47 6d [2] 69 6d [2] 56 71 }

  condition:
    any of them
}