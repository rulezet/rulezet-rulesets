rule TTP_XOR_WriteProcessMemory_dae8 {
  strings:
    $key_dae8 = { 8d 9a [2] bf b8 [2] b9 8d [2] 97 8d [2] a8 91 }

  condition:
    any of them
}