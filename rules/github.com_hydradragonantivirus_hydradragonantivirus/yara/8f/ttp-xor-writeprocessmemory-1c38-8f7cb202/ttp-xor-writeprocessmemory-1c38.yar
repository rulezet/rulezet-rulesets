rule TTP_XOR_WriteProcessMemory_1c38 {
  strings:
    $key_1c38 = { 4b 4a [2] 79 68 [2] 7f 5d [2] 51 5d [2] 6e 41 }

  condition:
    any of them
}