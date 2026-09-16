rule TTP_XOR_WriteProcessMemory_e544 {
  strings:
    $key_e544 = { b2 36 [2] 80 14 [2] 86 21 [2] a8 21 [2] 97 3d }

  condition:
    any of them
}