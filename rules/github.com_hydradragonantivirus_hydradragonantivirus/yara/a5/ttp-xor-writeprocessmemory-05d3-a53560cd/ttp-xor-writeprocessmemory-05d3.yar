rule TTP_XOR_WriteProcessMemory_05d3 {
  strings:
    $key_05d3 = { 52 a1 [2] 60 83 [2] 66 b6 [2] 48 b6 [2] 77 aa }

  condition:
    any of them
}