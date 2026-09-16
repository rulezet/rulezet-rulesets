rule TTP_XOR_WriteProcessMemory_1201 {
  strings:
    $key_1201 = { 45 73 [2] 77 51 [2] 71 64 [2] 5f 64 [2] 60 78 }

  condition:
    any of them
}