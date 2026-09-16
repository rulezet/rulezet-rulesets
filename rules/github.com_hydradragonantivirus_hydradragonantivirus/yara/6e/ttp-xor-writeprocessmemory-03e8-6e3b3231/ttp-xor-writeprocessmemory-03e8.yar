rule TTP_XOR_WriteProcessMemory_03e8 {
  strings:
    $key_03e8 = { 54 9a [2] 66 b8 [2] 60 8d [2] 4e 8d [2] 71 91 }

  condition:
    any of them
}