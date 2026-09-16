rule TTP_XOR_WriteProcessMemory_f898 {
  strings:
    $key_f898 = { af ea [2] 9d c8 [2] 9b fd [2] b5 fd [2] 8a e1 }

  condition:
    any of them
}