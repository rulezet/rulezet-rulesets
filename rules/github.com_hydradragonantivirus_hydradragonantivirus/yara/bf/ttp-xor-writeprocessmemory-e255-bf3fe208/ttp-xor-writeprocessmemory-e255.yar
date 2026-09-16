rule TTP_XOR_WriteProcessMemory_e255 {
  strings:
    $key_e255 = { b5 27 [2] 87 05 [2] 81 30 [2] af 30 [2] 90 2c }

  condition:
    any of them
}