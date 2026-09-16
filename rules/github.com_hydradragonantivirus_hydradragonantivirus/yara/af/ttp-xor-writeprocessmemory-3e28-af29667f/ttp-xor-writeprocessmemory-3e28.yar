rule TTP_XOR_WriteProcessMemory_3e28 {
  strings:
    $key_3e28 = { 69 5a [2] 5b 78 [2] 5d 4d [2] 73 4d [2] 4c 51 }

  condition:
    any of them
}