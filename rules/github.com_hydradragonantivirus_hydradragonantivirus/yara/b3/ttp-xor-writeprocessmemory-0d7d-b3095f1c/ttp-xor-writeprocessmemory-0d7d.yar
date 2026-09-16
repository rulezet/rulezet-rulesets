rule TTP_XOR_WriteProcessMemory_0d7d {
  strings:
    $key_0d7d = { 5a 0f [2] 68 2d [2] 6e 18 [2] 40 18 [2] 7f 04 }

  condition:
    any of them
}