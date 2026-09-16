rule TTP_XOR_WriteProcessMemory_ef2a {
  strings:
    $key_ef2a = { b8 58 [2] 8a 7a [2] 8c 4f [2] a2 4f [2] 9d 53 }

  condition:
    any of them
}