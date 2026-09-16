rule TTP_XOR_WriteProcessMemory_ee1b {
  strings:
    $key_ee1b = { b9 69 [2] 8b 4b [2] 8d 7e [2] a3 7e [2] 9c 62 }

  condition:
    any of them
}