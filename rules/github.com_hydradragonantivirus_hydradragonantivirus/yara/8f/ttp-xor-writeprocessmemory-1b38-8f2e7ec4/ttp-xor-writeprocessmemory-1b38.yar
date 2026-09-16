rule TTP_XOR_WriteProcessMemory_1b38 {
  strings:
    $key_1b38 = { 4c 4a [2] 7e 68 [2] 78 5d [2] 56 5d [2] 69 41 }

  condition:
    any of them
}