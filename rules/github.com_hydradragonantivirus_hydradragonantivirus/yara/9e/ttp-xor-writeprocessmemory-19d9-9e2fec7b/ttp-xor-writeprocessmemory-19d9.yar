rule TTP_XOR_WriteProcessMemory_19d9 {
  strings:
    $key_19d9 = { 4e ab [2] 7c 89 [2] 7a bc [2] 54 bc [2] 6b a0 }

  condition:
    any of them
}