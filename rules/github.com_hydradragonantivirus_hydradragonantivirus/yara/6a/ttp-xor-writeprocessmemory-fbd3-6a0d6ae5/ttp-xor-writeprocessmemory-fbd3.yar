rule TTP_XOR_WriteProcessMemory_fbd3 {
  strings:
    $key_fbd3 = { ac a1 [2] 9e 83 [2] 98 b6 [2] b6 b6 [2] 89 aa }

  condition:
    any of them
}