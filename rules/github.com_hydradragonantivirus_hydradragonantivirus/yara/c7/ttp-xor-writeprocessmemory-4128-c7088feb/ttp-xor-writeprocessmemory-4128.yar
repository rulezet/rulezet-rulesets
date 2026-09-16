rule TTP_XOR_WriteProcessMemory_4128 {
  strings:
    $key_4128 = { 16 5a [2] 24 78 [2] 22 4d [2] 0c 4d [2] 33 51 }

  condition:
    any of them
}