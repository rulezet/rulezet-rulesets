rule TTP_XOR_WriteProcessMemory_311b {
  strings:
    $key_311b = { 66 69 [2] 54 4b [2] 52 7e [2] 7c 7e [2] 43 62 }

  condition:
    any of them
}