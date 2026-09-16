rule TTP_XOR_WriteProcessMemory_71bf {
  strings:
    $key_71bf = { 26 cd [2] 14 ef [2] 12 da [2] 3c da [2] 03 c6 }

  condition:
    any of them
}