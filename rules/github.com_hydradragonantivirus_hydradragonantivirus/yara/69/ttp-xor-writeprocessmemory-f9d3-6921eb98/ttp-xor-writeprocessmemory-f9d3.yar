rule TTP_XOR_WriteProcessMemory_f9d3 {
  strings:
    $key_f9d3 = { ae a1 [2] 9c 83 [2] 9a b6 [2] b4 b6 [2] 8b aa }

  condition:
    any of them
}