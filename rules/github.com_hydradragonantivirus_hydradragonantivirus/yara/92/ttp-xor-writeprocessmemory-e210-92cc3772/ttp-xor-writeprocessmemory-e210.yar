rule TTP_XOR_WriteProcessMemory_e210 {
  strings:
    $key_e210 = { b5 62 [2] 87 40 [2] 81 75 [2] af 75 [2] 90 69 }

  condition:
    any of them
}