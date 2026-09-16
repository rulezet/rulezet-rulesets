rule TTP_XOR_WriteProcessMemory_e9e8 {
  strings:
    $key_e9e8 = { be 9a [2] 8c b8 [2] 8a 8d [2] a4 8d [2] 9b 91 }

  condition:
    any of them
}