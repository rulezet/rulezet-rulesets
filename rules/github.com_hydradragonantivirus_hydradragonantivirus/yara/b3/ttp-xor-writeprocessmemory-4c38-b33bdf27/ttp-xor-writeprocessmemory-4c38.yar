rule TTP_XOR_WriteProcessMemory_4c38 {
  strings:
    $key_4c38 = { 1b 4a [2] 29 68 [2] 2f 5d [2] 01 5d [2] 3e 41 }

  condition:
    any of them
}