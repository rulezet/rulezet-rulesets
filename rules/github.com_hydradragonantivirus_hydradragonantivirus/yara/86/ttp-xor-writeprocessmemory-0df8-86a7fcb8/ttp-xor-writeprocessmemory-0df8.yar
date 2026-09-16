rule TTP_XOR_WriteProcessMemory_0df8 {
  strings:
    $key_0df8 = { 5a 8a [2] 68 a8 [2] 6e 9d [2] 40 9d [2] 7f 81 }

  condition:
    any of them
}