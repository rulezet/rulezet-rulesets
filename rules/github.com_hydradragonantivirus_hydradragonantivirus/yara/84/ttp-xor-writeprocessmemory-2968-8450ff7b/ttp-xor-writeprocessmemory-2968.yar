rule TTP_XOR_WriteProcessMemory_2968 {
  strings:
    $key_2968 = { 7e 1a [2] 4c 38 [2] 4a 0d [2] 64 0d [2] 5b 11 }

  condition:
    any of them
}