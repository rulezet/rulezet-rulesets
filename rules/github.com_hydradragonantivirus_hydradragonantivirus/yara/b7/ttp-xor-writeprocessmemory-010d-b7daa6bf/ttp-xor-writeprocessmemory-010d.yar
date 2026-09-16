rule TTP_XOR_WriteProcessMemory_010d {
  strings:
    $key_010d = { 56 7f [2] 64 5d [2] 62 68 [2] 4c 68 [2] 73 74 }

  condition:
    any of them
}