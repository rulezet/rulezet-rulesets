rule TTP_XOR_WriteProcessMemory_ee1a {
  strings:
    $key_ee1a = { b9 68 [2] 8b 4a [2] 8d 7f [2] a3 7f [2] 9c 63 }

  condition:
    any of them
}