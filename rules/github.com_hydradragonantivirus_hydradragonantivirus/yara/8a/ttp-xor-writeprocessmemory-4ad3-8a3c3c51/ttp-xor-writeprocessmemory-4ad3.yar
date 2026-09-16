rule TTP_XOR_WriteProcessMemory_4ad3 {
  strings:
    $key_4ad3 = { 1d a1 [2] 2f 83 [2] 29 b6 [2] 07 b6 [2] 38 aa }

  condition:
    any of them
}