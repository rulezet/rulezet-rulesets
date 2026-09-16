rule TTP_XOR_WriteProcessMemory_2bce {
  strings:
    $key_2bce = { 7c bc [2] 4e 9e [2] 48 ab [2] 66 ab [2] 59 b7 }

  condition:
    any of them
}