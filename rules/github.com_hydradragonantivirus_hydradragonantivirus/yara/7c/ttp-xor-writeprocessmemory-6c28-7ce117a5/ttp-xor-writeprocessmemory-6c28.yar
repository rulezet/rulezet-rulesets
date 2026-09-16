rule TTP_XOR_WriteProcessMemory_6c28 {
  strings:
    $key_6c28 = { 3b 5a [2] 09 78 [2] 0f 4d [2] 21 4d [2] 1e 51 }

  condition:
    any of them
}