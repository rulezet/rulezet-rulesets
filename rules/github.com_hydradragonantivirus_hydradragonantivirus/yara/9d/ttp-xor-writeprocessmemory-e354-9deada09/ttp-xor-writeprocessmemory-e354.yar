rule TTP_XOR_WriteProcessMemory_e354 {
  strings:
    $key_e354 = { b4 26 [2] 86 04 [2] 80 31 [2] ae 31 [2] 91 2d }

  condition:
    any of them
}