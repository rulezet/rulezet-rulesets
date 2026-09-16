rule TTP_XOR_WriteProcessMemory_3117 {
  strings:
    $key_3117 = { 66 65 [2] 54 47 [2] 52 72 [2] 7c 72 [2] 43 6e }

  condition:
    any of them
}