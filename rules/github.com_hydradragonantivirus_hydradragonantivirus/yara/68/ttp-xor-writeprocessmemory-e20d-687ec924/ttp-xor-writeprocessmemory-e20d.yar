rule TTP_XOR_WriteProcessMemory_e20d {
  strings:
    $key_e20d = { b5 7f [2] 87 5d [2] 81 68 [2] af 68 [2] 90 74 }

  condition:
    any of them
}