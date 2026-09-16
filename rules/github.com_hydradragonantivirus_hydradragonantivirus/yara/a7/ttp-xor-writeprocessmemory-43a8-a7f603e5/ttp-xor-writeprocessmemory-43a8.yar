rule TTP_XOR_WriteProcessMemory_43a8 {
  strings:
    $key_43a8 = { 14 da [2] 26 f8 [2] 20 cd [2] 0e cd [2] 31 d1 }

  condition:
    any of them
}