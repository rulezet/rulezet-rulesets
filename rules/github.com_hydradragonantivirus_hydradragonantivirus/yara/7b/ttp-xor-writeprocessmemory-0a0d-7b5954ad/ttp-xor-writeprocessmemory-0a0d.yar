rule TTP_XOR_WriteProcessMemory_0a0d {
  strings:
    $key_0a0d = { 5d 7f [2] 6f 5d [2] 69 68 [2] 47 68 [2] 78 74 }

  condition:
    any of them
}