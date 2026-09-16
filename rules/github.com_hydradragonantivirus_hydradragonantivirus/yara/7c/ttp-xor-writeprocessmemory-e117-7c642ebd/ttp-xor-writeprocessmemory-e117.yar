rule TTP_XOR_WriteProcessMemory_e117 {
  strings:
    $key_e117 = { b6 65 [2] 84 47 [2] 82 72 [2] ac 72 [2] 93 6e }

  condition:
    any of them
}