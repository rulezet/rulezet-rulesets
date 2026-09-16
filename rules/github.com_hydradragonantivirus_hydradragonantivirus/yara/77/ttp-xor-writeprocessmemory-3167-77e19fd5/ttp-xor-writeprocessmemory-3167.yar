rule TTP_XOR_WriteProcessMemory_3167 {
  strings:
    $key_3167 = { 66 15 [2] 54 37 [2] 52 02 [2] 7c 02 [2] 43 1e }

  condition:
    any of them
}