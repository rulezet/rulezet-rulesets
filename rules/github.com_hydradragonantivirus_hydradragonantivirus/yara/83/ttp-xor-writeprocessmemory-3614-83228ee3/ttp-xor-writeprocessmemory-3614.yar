rule TTP_XOR_WriteProcessMemory_3614 {
  strings:
    $key_3614 = { 61 66 [2] 53 44 [2] 55 71 [2] 7b 71 [2] 44 6d }

  condition:
    any of them
}