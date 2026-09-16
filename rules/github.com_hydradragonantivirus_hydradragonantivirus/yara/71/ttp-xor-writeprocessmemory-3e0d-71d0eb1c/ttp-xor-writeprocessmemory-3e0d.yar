rule TTP_XOR_WriteProcessMemory_3e0d {
  strings:
    $key_3e0d = { 69 7f [2] 5b 5d [2] 5d 68 [2] 73 68 [2] 4c 74 }

  condition:
    any of them
}