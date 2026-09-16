rule TTP_XOR_WriteProcessMemory_2bd3 {
  strings:
    $key_2bd3 = { 7c a1 [2] 4e 83 [2] 48 b6 [2] 66 b6 [2] 59 aa }

  condition:
    any of them
}