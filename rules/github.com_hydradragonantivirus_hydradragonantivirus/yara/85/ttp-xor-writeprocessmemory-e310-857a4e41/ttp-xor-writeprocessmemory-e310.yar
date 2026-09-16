rule TTP_XOR_WriteProcessMemory_e310 {
  strings:
    $key_e310 = { b4 62 [2] 86 40 [2] 80 75 [2] ae 75 [2] 91 69 }

  condition:
    any of them
}