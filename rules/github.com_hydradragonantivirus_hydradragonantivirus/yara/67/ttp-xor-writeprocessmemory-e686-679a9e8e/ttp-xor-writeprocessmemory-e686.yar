rule TTP_XOR_WriteProcessMemory_e686 {
  strings:
    $key_e686 = { b1 f4 [2] 83 d6 [2] 85 e3 [2] ab e3 [2] 94 ff }

  condition:
    any of them
}