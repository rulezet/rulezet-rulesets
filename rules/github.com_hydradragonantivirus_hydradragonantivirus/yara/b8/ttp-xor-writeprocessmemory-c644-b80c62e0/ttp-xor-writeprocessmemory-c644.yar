rule TTP_XOR_WriteProcessMemory_c644 {
  strings:
    $key_c644 = { 91 36 [2] a3 14 [2] a5 21 [2] 8b 21 [2] b4 3d }

  condition:
    any of them
}