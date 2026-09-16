rule TTP_XOR_WriteProcessMemory_f828 {
  strings:
    $key_f828 = { af 5a [2] 9d 78 [2] 9b 4d [2] b5 4d [2] 8a 51 }

  condition:
    any of them
}