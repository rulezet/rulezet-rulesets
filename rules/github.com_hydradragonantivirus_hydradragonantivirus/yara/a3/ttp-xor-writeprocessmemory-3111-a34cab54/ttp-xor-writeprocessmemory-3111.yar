rule TTP_XOR_WriteProcessMemory_3111 {
  strings:
    $key_3111 = { 66 63 [2] 54 41 [2] 52 74 [2] 7c 74 [2] 43 68 }

  condition:
    any of them
}