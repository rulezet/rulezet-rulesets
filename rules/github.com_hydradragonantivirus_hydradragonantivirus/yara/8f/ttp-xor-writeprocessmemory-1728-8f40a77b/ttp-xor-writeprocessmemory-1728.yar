rule TTP_XOR_WriteProcessMemory_1728 {
  strings:
    $key_1728 = { 40 5a [2] 72 78 [2] 74 4d [2] 5a 4d [2] 65 51 }

  condition:
    any of them
}