rule TTP_XOR_WriteProcessMemory_563d {
  strings:
    $key_563d = { 01 4f [2] 33 6d [2] 35 58 [2] 1b 58 [2] 24 44 }

  condition:
    any of them
}