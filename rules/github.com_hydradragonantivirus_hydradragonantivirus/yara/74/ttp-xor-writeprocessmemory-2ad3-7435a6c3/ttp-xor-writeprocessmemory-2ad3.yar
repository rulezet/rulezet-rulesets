rule TTP_XOR_WriteProcessMemory_2ad3 {
  strings:
    $key_2ad3 = { 7d a1 [2] 4f 83 [2] 49 b6 [2] 67 b6 [2] 58 aa }

  condition:
    any of them
}