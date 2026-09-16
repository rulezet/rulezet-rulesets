rule TTP_XOR_WriteProcessMemory_ef3a {
  strings:
    $key_ef3a = { b8 48 [2] 8a 6a [2] 8c 5f [2] a2 5f [2] 9d 43 }

  condition:
    any of them
}