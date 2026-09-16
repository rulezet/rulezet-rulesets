rule TTP_XOR_WriteProcessMemory_2b1a {
  strings:
    $key_2b1a = { 7c 68 [2] 4e 4a [2] 48 7f [2] 66 7f [2] 59 63 }

  condition:
    any of them
}