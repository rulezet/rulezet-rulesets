rule TTP_XOR_WriteProcessMemory_56e8 {
  strings:
    $key_56e8 = { 01 9a [2] 33 b8 [2] 35 8d [2] 1b 8d [2] 24 91 }

  condition:
    any of them
}