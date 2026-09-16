rule TTP_XOR_WriteProcessMemory_f82a {
  strings:
    $key_f82a = { af 58 [2] 9d 7a [2] 9b 4f [2] b5 4f [2] 8a 53 }

  condition:
    any of them
}