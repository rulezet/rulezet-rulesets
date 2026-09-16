rule TTP_XOR_WriteProcessMemory_117d {
  strings:
    $key_117d = { 46 0f [2] 74 2d [2] 72 18 [2] 5c 18 [2] 63 04 }

  condition:
    any of them
}