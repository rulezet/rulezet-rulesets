rule TTP_XOR_WriteProcessMemory_3147 {
  strings:
    $key_3147 = { 66 35 [2] 54 17 [2] 52 22 [2] 7c 22 [2] 43 3e }

  condition:
    any of them
}