rule TTP_XOR_WriteProcessMemory_3ba8 {
  strings:
    $key_3ba8 = { 6c da [2] 5e f8 [2] 58 cd [2] 76 cd [2] 49 d1 }

  condition:
    any of them
}