rule TTP_XOR_WriteProcessMemory_f865 {
  strings:
    $key_f865 = { af 17 [2] 9d 35 [2] 9b 00 [2] b5 00 [2] 8a 1c }

  condition:
    any of them
}