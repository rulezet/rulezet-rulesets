rule TTP_XOR_WriteProcessMemory_6d38 {
  strings:
    $key_6d38 = { 3a 4a [2] 08 68 [2] 0e 5d [2] 20 5d [2] 1f 41 }

  condition:
    any of them
}