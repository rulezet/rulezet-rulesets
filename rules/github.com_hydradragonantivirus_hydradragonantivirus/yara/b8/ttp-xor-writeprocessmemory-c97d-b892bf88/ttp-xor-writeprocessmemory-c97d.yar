rule TTP_XOR_WriteProcessMemory_c97d {
  strings:
    $key_c97d = { 9e 0f [2] ac 2d [2] aa 18 [2] 84 18 [2] bb 04 }

  condition:
    any of them
}