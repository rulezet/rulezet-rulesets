rule TTP_XOR_WriteProcessMemory_f8e8 {
  strings:
    $key_f8e8 = { af 9a [2] 9d b8 [2] 9b 8d [2] b5 8d [2] 8a 91 }

  condition:
    any of them
}