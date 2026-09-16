rule TTP_XOR_WriteProcessMemory_3c0d {
  strings:
    $key_3c0d = { 6b 7f [2] 59 5d [2] 5f 68 [2] 71 68 [2] 4e 74 }

  condition:
    any of them
}