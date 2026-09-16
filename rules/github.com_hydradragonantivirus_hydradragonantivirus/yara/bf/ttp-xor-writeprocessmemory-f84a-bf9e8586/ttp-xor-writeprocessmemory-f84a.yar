rule TTP_XOR_WriteProcessMemory_f84a {
  strings:
    $key_f84a = { af 38 [2] 9d 1a [2] 9b 2f [2] b5 2f [2] 8a 33 }

  condition:
    any of them
}