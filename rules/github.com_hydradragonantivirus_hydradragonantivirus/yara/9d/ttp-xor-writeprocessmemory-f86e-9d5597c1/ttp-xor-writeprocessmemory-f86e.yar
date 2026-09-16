rule TTP_XOR_WriteProcessMemory_f86e {
  strings:
    $key_f86e = { af 1c [2] 9d 3e [2] 9b 0b [2] b5 0b [2] 8a 17 }

  condition:
    any of them
}