rule TTP_XOR_WriteProcessMemory_4c93 {
  strings:
    $key_4c93 = { 1b e1 [2] 29 c3 [2] 2f f6 [2] 01 f6 [2] 3e ea }

  condition:
    any of them
}