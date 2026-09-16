rule TTP_XOR_WriteProcessMemory_389d {
  strings:
    $key_389d = { 6f ef [2] 5d cd [2] 5b f8 [2] 75 f8 [2] 4a e4 }

  condition:
    any of them
}