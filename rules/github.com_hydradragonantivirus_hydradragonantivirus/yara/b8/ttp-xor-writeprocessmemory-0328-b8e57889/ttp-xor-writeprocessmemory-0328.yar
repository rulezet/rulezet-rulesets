rule TTP_XOR_WriteProcessMemory_0328 {
  strings:
    $key_0328 = { 54 5a [2] 66 78 [2] 60 4d [2] 4e 4d [2] 71 51 }

  condition:
    any of them
}