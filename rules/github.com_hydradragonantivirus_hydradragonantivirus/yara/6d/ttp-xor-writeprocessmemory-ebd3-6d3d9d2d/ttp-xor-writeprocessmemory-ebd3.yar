rule TTP_XOR_WriteProcessMemory_ebd3 {
  strings:
    $key_ebd3 = { bc a1 [2] 8e 83 [2] 88 b6 [2] a6 b6 [2] 99 aa }

  condition:
    any of them
}