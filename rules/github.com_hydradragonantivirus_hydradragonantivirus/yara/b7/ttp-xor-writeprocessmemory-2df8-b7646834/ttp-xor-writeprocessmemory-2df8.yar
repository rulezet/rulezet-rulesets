rule TTP_XOR_WriteProcessMemory_2df8 {
  strings:
    $key_2df8 = { 7a 8a [2] 48 a8 [2] 4e 9d [2] 60 9d [2] 5f 81 }

  condition:
    any of them
}