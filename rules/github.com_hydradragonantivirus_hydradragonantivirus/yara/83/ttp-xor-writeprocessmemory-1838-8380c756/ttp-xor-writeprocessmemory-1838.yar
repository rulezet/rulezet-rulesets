rule TTP_XOR_WriteProcessMemory_1838 {
  strings:
    $key_1838 = { 4f 4a [2] 7d 68 [2] 7b 5d [2] 55 5d [2] 6a 41 }

  condition:
    any of them
}