rule TTP_XOR_WriteProcessMemory_d8d9 {
  strings:
    $key_d8d9 = { 8f ab [2] bd 89 [2] bb bc [2] 95 bc [2] aa a0 }

  condition:
    any of them
}