rule TTP_XOR_WriteProcessMemory_2908 {
  strings:
    $key_2908 = { 7e 7a [2] 4c 58 [2] 4a 6d [2] 64 6d [2] 5b 71 }

  condition:
    any of them
}