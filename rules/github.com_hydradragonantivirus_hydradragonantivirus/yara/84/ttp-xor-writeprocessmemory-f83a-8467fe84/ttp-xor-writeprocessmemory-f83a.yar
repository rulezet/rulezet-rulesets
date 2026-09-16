rule TTP_XOR_WriteProcessMemory_f83a {
  strings:
    $key_f83a = { af 48 [2] 9d 6a [2] 9b 5f [2] b5 5f [2] 8a 43 }

  condition:
    any of them
}