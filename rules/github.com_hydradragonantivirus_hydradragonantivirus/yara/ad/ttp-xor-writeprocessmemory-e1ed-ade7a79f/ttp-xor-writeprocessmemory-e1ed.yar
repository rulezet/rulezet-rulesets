rule TTP_XOR_WriteProcessMemory_e1ed {
  strings:
    $key_e1ed = { b6 9f [2] 84 bd [2] 82 88 [2] ac 88 [2] 93 94 }

  condition:
    any of them
}