rule TTP_XOR_WriteProcessMemory_2614 {
  strings:
    $key_2614 = { 71 66 [2] 43 44 [2] 45 71 [2] 6b 71 [2] 54 6d }

  condition:
    any of them
}