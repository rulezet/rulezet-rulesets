rule TTP_XOR_WriteProcessMemory_ef5a {
  strings:
    $key_ef5a = { b8 28 [2] 8a 0a [2] 8c 3f [2] a2 3f [2] 9d 23 }

  condition:
    any of them
}