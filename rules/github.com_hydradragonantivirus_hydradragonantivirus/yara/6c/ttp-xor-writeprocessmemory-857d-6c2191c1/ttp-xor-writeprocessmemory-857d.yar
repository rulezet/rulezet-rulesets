rule TTP_XOR_WriteProcessMemory_857d {
  strings:
    $key_857d = { d2 0f [2] e0 2d [2] e6 18 [2] c8 18 [2] f7 04 }

  condition:
    any of them
}