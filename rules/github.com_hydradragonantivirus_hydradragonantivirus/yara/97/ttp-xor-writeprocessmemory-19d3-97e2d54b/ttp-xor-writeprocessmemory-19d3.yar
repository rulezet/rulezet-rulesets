rule TTP_XOR_WriteProcessMemory_19d3 {
  strings:
    $key_19d3 = { 4e a1 [2] 7c 83 [2] 7a b6 [2] 54 b6 [2] 6b aa }

  condition:
    any of them
}