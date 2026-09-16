rule TTP_XOR_WriteProcessMemory_fe31 {
  strings:
    $key_fe31 = { a9 43 [2] 9b 61 [2] 9d 54 [2] b3 54 [2] 8c 48 }

  condition:
    any of them
}