rule TTP_XOR_WriteProcessMemory_f82d {
  strings:
    $key_f82d = { af 5f [2] 9d 7d [2] 9b 48 [2] b5 48 [2] 8a 54 }

  condition:
    any of them
}