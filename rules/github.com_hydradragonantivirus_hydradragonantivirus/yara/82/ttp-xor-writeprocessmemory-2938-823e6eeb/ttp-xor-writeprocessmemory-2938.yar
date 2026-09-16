rule TTP_XOR_WriteProcessMemory_2938 {
  strings:
    $key_2938 = { 7e 4a [2] 4c 68 [2] 4a 5d [2] 64 5d [2] 5b 41 }

  condition:
    any of them
}