rule TTP_XOR_WriteProcessMemory_36e8 {
  strings:
    $key_36e8 = { 61 9a [2] 53 b8 [2] 55 8d [2] 7b 8d [2] 44 91 }

  condition:
    any of them
}