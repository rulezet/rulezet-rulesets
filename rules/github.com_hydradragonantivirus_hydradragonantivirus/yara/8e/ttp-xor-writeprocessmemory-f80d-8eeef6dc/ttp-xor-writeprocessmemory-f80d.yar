rule TTP_XOR_WriteProcessMemory_f80d {
  strings:
    $key_f80d = { af 7f [2] 9d 5d [2] 9b 68 [2] b5 68 [2] 8a 74 }

  condition:
    any of them
}