rule TTP_XOR_WriteProcessMemory_3301 {
  strings:
    $key_3301 = { 64 73 [2] 56 51 [2] 50 64 [2] 7e 64 [2] 41 78 }

  condition:
    any of them
}