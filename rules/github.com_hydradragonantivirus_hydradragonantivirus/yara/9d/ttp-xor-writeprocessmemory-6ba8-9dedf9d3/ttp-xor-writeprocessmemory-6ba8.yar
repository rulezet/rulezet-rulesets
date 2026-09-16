rule TTP_XOR_WriteProcessMemory_6ba8 {
  strings:
    $key_6ba8 = { 3c da [2] 0e f8 [2] 08 cd [2] 26 cd [2] 19 d1 }

  condition:
    any of them
}