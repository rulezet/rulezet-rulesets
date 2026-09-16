rule TTP_XOR_WriteProcessMemory_f8e9 {
  strings:
    $key_f8e9 = { af 9b [2] 9d b9 [2] 9b 8c [2] b5 8c [2] 8a 90 }

  condition:
    any of them
}