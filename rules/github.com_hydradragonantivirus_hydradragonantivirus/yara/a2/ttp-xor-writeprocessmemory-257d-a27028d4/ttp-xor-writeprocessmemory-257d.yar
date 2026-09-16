rule TTP_XOR_WriteProcessMemory_257d {
  strings:
    $key_257d = { 72 0f [2] 40 2d [2] 46 18 [2] 68 18 [2] 57 04 }

  condition:
    any of them
}