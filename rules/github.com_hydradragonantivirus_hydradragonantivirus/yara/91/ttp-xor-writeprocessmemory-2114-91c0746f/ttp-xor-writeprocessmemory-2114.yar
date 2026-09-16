rule TTP_XOR_WriteProcessMemory_2114 {
  strings:
    $key_2114 = { 76 66 [2] 44 44 [2] 42 71 [2] 6c 71 [2] 53 6d }

  condition:
    any of them
}