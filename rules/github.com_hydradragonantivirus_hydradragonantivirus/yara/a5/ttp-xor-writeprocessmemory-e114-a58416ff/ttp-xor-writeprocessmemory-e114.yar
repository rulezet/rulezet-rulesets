rule TTP_XOR_WriteProcessMemory_e114 {
  strings:
    $key_e114 = { b6 66 [2] 84 44 [2] 82 71 [2] ac 71 [2] 93 6d }

  condition:
    any of them
}