rule TTP_XOR_WriteProcessMemory_517d {
  strings:
    $key_517d = { 06 0f [2] 34 2d [2] 32 18 [2] 1c 18 [2] 23 04 }

  condition:
    any of them
}