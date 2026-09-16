rule TTP_XOR_WriteProcessMemory_2cf8 {
  strings:
    $key_2cf8 = { 7b 8a [2] 49 a8 [2] 4f 9d [2] 61 9d [2] 5e 81 }

  condition:
    any of them
}