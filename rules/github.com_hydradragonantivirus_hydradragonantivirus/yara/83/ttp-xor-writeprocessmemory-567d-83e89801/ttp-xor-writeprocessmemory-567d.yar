rule TTP_XOR_WriteProcessMemory_567d {
  strings:
    $key_567d = { 01 0f [2] 33 2d [2] 35 18 [2] 1b 18 [2] 24 04 }

  condition:
    any of them
}