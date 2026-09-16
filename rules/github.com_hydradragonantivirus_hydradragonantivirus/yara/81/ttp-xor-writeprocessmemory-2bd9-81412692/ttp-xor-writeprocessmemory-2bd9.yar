rule TTP_XOR_WriteProcessMemory_2bd9 {
  strings:
    $key_2bd9 = { 7c ab [2] 4e 89 [2] 48 bc [2] 66 bc [2] 59 a0 }

  condition:
    any of them
}