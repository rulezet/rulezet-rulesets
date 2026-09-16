rule TTP_XOR_WriteProcessMemory_e111 {
  strings:
    $key_e111 = { b6 63 [2] 84 41 [2] 82 74 [2] ac 74 [2] 93 68 }

  condition:
    any of them
}