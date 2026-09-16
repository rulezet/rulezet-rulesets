rule TTP_XOR_WriteProcessMemory_031b {
  strings:
    $key_031b = { 54 69 [2] 66 4b [2] 60 7e [2] 4e 7e [2] 71 62 }

  condition:
    any of them
}