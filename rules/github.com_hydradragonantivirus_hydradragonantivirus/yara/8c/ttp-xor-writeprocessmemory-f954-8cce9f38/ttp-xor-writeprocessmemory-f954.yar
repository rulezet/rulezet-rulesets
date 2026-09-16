rule TTP_XOR_WriteProcessMemory_f954 {
  strings:
    $key_f954 = { ae 26 [2] 9c 04 [2] 9a 31 [2] b4 31 [2] 8b 2d }

  condition:
    any of them
}