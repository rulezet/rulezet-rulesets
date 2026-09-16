rule TTP_XOR_WriteProcessMemory_5ba8 {
  strings:
    $key_5ba8 = { 0c da [2] 3e f8 [2] 38 cd [2] 16 cd [2] 29 d1 }

  condition:
    any of them
}