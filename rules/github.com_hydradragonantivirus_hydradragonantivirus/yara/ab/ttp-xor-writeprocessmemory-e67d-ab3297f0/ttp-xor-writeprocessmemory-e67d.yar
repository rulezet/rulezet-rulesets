rule TTP_XOR_WriteProcessMemory_e67d {
  strings:
    $key_e67d = { b1 0f [2] 83 2d [2] 85 18 [2] ab 18 [2] 94 04 }

  condition:
    any of them
}