rule TTP_XOR_WriteProcessMemory_2647 {
  strings:
    $key_2647 = { 71 35 [2] 43 17 [2] 45 22 [2] 6b 22 [2] 54 3e }

  condition:
    any of them
}