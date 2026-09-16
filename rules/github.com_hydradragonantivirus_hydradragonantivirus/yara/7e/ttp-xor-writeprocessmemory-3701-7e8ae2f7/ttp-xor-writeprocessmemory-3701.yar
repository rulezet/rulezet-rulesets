rule TTP_XOR_WriteProcessMemory_3701 {
  strings:
    $key_3701 = { 60 73 [2] 52 51 [2] 54 64 [2] 7a 64 [2] 45 78 }

  condition:
    any of them
}