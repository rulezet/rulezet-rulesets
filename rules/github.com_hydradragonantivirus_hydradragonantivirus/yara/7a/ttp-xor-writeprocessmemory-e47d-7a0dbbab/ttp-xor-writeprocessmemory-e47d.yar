rule TTP_XOR_WriteProcessMemory_e47d {
  strings:
    $key_e47d = { b3 0f [2] 81 2d [2] 87 18 [2] a9 18 [2] 96 04 }

  condition:
    any of them
}