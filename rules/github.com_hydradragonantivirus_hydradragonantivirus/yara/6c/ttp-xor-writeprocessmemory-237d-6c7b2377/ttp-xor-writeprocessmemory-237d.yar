rule TTP_XOR_WriteProcessMemory_237d {
  strings:
    $key_237d = { 74 0f [2] 46 2d [2] 40 18 [2] 6e 18 [2] 51 04 }

  condition:
    any of them
}