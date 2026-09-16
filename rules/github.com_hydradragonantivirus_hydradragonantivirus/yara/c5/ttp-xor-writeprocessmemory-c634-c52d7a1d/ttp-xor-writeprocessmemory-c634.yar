rule TTP_XOR_WriteProcessMemory_c634 {
  strings:
    $key_c634 = { 91 46 [2] a3 64 [2] a5 51 [2] 8b 51 [2] b4 4d }

  condition:
    any of them
}