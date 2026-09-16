rule TTP_XOR_WriteProcessMemory_09d9 {
  strings:
    $key_09d9 = { 5e ab [2] 6c 89 [2] 6a bc [2] 44 bc [2] 7b a0 }

  condition:
    any of them
}