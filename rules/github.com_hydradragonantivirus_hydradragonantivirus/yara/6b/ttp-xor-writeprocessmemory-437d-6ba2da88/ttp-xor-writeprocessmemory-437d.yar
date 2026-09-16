rule TTP_XOR_WriteProcessMemory_437d {
  strings:
    $key_437d = { 14 0f [2] 26 2d [2] 20 18 [2] 0e 18 [2] 31 04 }

  condition:
    any of them
}