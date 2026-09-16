rule TTP_XOR_WriteProcessMemory_2686 {
  strings:
    $key_2686 = { 71 f4 [2] 43 d6 [2] 45 e3 [2] 6b e3 [2] 54 ff }

  condition:
    any of them
}