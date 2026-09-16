rule TTP_XOR_WriteProcessMemory_e92a {
  strings:
    $key_e92a = { be 58 [2] 8c 7a [2] 8a 4f [2] a4 4f [2] 9b 53 }

  condition:
    any of them
}