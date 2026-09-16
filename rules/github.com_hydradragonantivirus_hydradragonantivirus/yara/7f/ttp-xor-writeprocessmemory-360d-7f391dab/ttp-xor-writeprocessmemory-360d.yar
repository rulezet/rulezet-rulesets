rule TTP_XOR_WriteProcessMemory_360d {
  strings:
    $key_360d = { 61 7f [2] 53 5d [2] 55 68 [2] 7b 68 [2] 44 74 }

  condition:
    any of them
}