rule TTP_XOR_WriteProcessMemory_0ad3 {
  strings:
    $key_0ad3 = { 5d a1 [2] 6f 83 [2] 69 b6 [2] 47 b6 [2] 78 aa }

  condition:
    any of them
}