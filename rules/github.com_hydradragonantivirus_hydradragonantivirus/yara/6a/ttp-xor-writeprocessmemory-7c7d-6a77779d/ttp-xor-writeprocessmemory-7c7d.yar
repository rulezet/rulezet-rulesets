rule TTP_XOR_WriteProcessMemory_7c7d {
  strings:
    $key_7c7d = { 2b 0f [2] 19 2d [2] 1f 18 [2] 31 18 [2] 0e 04 }

  condition:
    any of them
}