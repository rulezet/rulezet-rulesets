rule TTP_XOR_WriteProcessMemory_33e8 {
  strings:
    $key_33e8 = { 64 9a [2] 56 b8 [2] 50 8d [2] 7e 8d [2] 41 91 }

  condition:
    any of them
}