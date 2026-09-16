rule TTP_XOR_WriteProcessMemory_e13c {
  strings:
    $key_e13c = { b6 4e [2] 84 6c [2] 82 59 [2] ac 59 [2] 93 45 }

  condition:
    any of them
}