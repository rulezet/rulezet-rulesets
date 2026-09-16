rule TTP_XOR_WriteProcessMemory_4738 {
  strings:
    $key_4738 = { 10 4a [2] 22 68 [2] 24 5d [2] 0a 5d [2] 35 41 }

  condition:
    any of them
}