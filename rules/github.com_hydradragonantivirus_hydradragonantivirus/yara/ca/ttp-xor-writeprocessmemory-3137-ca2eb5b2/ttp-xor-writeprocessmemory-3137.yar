rule TTP_XOR_WriteProcessMemory_3137 {
  strings:
    $key_3137 = { 66 45 [2] 54 67 [2] 52 52 [2] 7c 52 [2] 43 4e }

  condition:
    any of them
}