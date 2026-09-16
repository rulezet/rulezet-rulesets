rule TTP_XOR_WriteProcessMemory_72ce {
  strings:
    $key_72ce = { 25 bc [2] 17 9e [2] 11 ab [2] 3f ab [2] 00 b7 }

  condition:
    any of them
}