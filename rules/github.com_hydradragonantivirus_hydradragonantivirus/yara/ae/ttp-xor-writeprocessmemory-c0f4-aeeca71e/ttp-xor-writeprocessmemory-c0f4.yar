rule TTP_XOR_WriteProcessMemory_c0f4 {
  strings:
    $key_c0f4 = { 97 86 [2] a5 a4 [2] a3 91 [2] 8d 91 [2] b2 8d }

  condition:
    any of them
}