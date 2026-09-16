rule TTP_XOR_WriteProcessMemory_2e28 {
  strings:
    $key_2e28 = { 79 5a [2] 4b 78 [2] 4d 4d [2] 63 4d [2] 5c 51 }

  condition:
    any of them
}