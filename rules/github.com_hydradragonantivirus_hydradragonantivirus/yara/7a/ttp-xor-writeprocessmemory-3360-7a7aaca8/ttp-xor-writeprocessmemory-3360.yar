rule TTP_XOR_WriteProcessMemory_3360 {
  strings:
    $key_3360 = { 64 12 [2] 56 30 [2] 50 05 [2] 7e 05 [2] 41 19 }

  condition:
    any of them
}