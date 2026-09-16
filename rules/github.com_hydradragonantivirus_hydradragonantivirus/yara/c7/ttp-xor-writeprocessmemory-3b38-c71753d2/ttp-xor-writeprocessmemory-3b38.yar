rule TTP_XOR_WriteProcessMemory_3b38 {
  strings:
    $key_3b38 = { 6c 4a [2] 5e 68 [2] 58 5d [2] 76 5d [2] 49 41 }

  condition:
    any of them
}