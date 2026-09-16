rule TTP_XOR_WriteProcessMemory_4b7d {
  strings:
    $key_4b7d = { 1c 0f [2] 2e 2d [2] 28 18 [2] 06 18 [2] 39 04 }

  condition:
    any of them
}