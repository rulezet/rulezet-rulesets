rule TTP_XOR_WriteProcessMemory_32d3 {
  strings:
    $key_32d3 = { 65 a1 [2] 57 83 [2] 51 b6 [2] 7f b6 [2] 40 aa }

  condition:
    any of them
}