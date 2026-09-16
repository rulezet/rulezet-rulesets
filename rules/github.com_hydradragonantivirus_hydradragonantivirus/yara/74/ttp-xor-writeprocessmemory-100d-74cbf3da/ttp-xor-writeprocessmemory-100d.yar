rule TTP_XOR_WriteProcessMemory_100d {
  strings:
    $key_100d = { 47 7f [2] 75 5d [2] 73 68 [2] 5d 68 [2] 62 74 }

  condition:
    any of them
}