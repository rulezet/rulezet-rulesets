rule TTP_XOR_WriteProcessMemory_e71a {
  strings:
    $key_e71a = { b0 68 [2] 82 4a [2] 84 7f [2] aa 7f [2] 95 63 }

  condition:
    any of them
}