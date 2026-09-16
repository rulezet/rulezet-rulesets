rule TTP_XOR_WriteProcessMemory_5b38 {
  strings:
    $key_5b38 = { 0c 4a [2] 3e 68 [2] 38 5d [2] 16 5d [2] 29 41 }

  condition:
    any of them
}