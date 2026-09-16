rule TTP_XOR_WriteProcessMemory_ec7d {
  strings:
    $key_ec7d = { bb 0f [2] 89 2d [2] 8f 18 [2] a1 18 [2] 9e 04 }

  condition:
    any of them
}