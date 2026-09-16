rule TTP_XOR_WriteProcessMemory_587d {
  strings:
    $key_587d = { 0f 0f [2] 3d 2d [2] 3b 18 [2] 15 18 [2] 2a 04 }

  condition:
    any of them
}