rule TTP_XOR_WriteProcessMemory_dc30 {
  strings:
    $key_dc30 = { 8b 42 [2] b9 60 [2] bf 55 [2] 91 55 [2] ae 49 }

  condition:
    any of them
}