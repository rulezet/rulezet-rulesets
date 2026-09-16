rule TTP_XOR_WriteProcessMemory_e621 {
  strings:
    $key_e621 = { b1 53 [2] 83 71 [2] 85 44 [2] ab 44 [2] 94 58 }

  condition:
    any of them
}