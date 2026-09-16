rule TTP_XOR_WriteProcessMemory_f925 {
  strings:
    $key_f925 = { ae 57 [2] 9c 75 [2] 9a 40 [2] b4 40 [2] 8b 5c }

  condition:
    any of them
}