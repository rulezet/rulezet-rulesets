rule TTP_XOR_WriteProcessMemory_5806 {
  strings:
    $key_5806 = { 0f 74 [2] 3d 56 [2] 3b 63 [2] 15 63 [2] 2a 7f }

  condition:
    any of them
}