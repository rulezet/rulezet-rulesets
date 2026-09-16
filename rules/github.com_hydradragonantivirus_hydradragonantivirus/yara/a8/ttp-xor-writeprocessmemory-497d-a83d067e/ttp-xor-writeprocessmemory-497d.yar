rule TTP_XOR_WriteProcessMemory_497d {
  strings:
    $key_497d = { 1e 0f [2] 2c 2d [2] 2a 18 [2] 04 18 [2] 3b 04 }

  condition:
    any of them
}