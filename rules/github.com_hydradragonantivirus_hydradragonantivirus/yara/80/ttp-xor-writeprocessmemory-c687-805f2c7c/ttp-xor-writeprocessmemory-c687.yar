rule TTP_XOR_WriteProcessMemory_c687 {
  strings:
    $key_c687 = { 91 f5 [2] a3 d7 [2] a5 e2 [2] 8b e2 [2] b4 fe }

  condition:
    any of them
}