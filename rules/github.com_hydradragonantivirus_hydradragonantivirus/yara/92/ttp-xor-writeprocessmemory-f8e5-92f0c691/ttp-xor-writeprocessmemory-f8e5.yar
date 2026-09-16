rule TTP_XOR_WriteProcessMemory_f8e5 {
  strings:
    $key_f8e5 = { af 97 [2] 9d b5 [2] 9b 80 [2] b5 80 [2] 8a 9c }

  condition:
    any of them
}