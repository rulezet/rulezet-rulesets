rule TTP_XOR_WriteProcessMemory_4c28 {
  strings:
    $key_4c28 = { 1b 5a [2] 29 78 [2] 2f 4d [2] 01 4d [2] 3e 51 }

  condition:
    any of them
}