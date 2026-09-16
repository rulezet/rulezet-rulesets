rule TTP_XOR_WriteProcessMemory_4728 {
  strings:
    $key_4728 = { 10 5a [2] 22 78 [2] 24 4d [2] 0a 4d [2] 35 51 }

  condition:
    any of them
}