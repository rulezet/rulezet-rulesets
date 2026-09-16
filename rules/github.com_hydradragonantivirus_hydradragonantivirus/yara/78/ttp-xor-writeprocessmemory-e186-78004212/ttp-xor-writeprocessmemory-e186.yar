rule TTP_XOR_WriteProcessMemory_e186 {
  strings:
    $key_e186 = { b6 f4 [2] 84 d6 [2] 82 e3 [2] ac e3 [2] 93 ff }

  condition:
    any of them
}