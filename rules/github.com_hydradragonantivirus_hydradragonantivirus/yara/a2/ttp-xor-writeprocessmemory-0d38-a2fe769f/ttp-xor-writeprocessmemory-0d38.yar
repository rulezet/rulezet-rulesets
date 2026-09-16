rule TTP_XOR_WriteProcessMemory_0d38 {
  strings:
    $key_0d38 = { 5a 4a [2] 68 68 [2] 6e 5d [2] 40 5d [2] 7f 41 }

  condition:
    any of them
}