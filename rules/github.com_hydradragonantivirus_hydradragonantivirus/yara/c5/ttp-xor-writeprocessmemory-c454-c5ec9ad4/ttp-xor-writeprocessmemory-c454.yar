rule TTP_XOR_WriteProcessMemory_c454 {
  strings:
    $key_c454 = { 93 26 [2] a1 04 [2] a7 31 [2] 89 31 [2] b6 2d }

  condition:
    any of them
}