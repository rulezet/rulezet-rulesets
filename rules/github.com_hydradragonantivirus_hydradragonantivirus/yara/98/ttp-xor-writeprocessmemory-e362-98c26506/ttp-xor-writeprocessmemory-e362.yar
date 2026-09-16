rule TTP_XOR_WriteProcessMemory_e362 {
  strings:
    $key_e362 = { b4 10 [2] 86 32 [2] 80 07 [2] ae 07 [2] 91 1b }

  condition:
    any of them
}