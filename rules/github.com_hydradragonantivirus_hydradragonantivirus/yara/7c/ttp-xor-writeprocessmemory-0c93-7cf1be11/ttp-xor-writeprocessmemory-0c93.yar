rule TTP_XOR_WriteProcessMemory_0c93 {
  strings:
    $key_0c93 = { 5b e1 [2] 69 c3 [2] 6f f6 [2] 41 f6 [2] 7e ea }

  condition:
    any of them
}