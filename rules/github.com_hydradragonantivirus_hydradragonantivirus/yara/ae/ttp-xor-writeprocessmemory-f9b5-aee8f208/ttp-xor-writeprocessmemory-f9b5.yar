rule TTP_XOR_WriteProcessMemory_f9b5 {
  strings:
    $key_f9b5 = { ae c7 [2] 9c e5 [2] 9a d0 [2] b4 d0 [2] 8b cc }

  condition:
    any of them
}