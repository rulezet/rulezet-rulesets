rule TTP_XOR_WriteProcessMemory_e91a {
  strings:
    $key_e91a = { be 68 [2] 8c 4a [2] 8a 7f [2] a4 7f [2] 9b 63 }

  condition:
    any of them
}