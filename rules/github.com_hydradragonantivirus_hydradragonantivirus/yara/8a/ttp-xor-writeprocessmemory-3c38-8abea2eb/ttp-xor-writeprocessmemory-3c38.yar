rule TTP_XOR_WriteProcessMemory_3c38 {
  strings:
    $key_3c38 = { 6b 4a [2] 59 68 [2] 5f 5d [2] 71 5d [2] 4e 41 }

  condition:
    any of them
}