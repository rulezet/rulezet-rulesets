rule TTP_XOR_WriteProcessMemory_319d {
  strings:
    $key_319d = { 66 ef [2] 54 cd [2] 52 f8 [2] 7c f8 [2] 43 e4 }

  condition:
    any of them
}