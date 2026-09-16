rule TTP_XOR_WriteProcessMemory_e119 {
  strings:
    $key_e119 = { b6 6b [2] 84 49 [2] 82 7c [2] ac 7c [2] 93 60 }

  condition:
    any of them
}