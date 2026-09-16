rule TTP_XOR_WriteProcessMemory_0d93 {
  strings:
    $key_0d93 = { 5a e1 [2] 68 c3 [2] 6e f6 [2] 40 f6 [2] 7f ea }

  condition:
    any of them
}