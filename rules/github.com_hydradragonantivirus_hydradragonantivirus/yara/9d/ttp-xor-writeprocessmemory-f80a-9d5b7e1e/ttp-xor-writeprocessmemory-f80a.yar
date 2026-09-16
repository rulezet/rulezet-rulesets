rule TTP_XOR_WriteProcessMemory_f80a {
  strings:
    $key_f80a = { af 78 [2] 9d 5a [2] 9b 6f [2] b5 6f [2] 8a 73 }

  condition:
    any of them
}