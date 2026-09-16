rule TTP_XOR_WriteProcessMemory_d47d {
  strings:
    $key_d47d = { 83 0f [2] b1 2d [2] b7 18 [2] 99 18 [2] a6 04 }

  condition:
    any of them
}