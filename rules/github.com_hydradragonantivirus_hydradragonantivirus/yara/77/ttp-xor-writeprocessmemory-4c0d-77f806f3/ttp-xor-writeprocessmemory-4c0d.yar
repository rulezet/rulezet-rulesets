rule TTP_XOR_WriteProcessMemory_4c0d {
  strings:
    $key_4c0d = { 1b 7f [2] 29 5d [2] 2f 68 [2] 01 68 [2] 3e 74 }

  condition:
    any of them
}