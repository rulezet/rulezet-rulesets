rule TTP_XOR_WriteProcessMemory_ef0a {
  strings:
    $key_ef0a = { b8 78 [2] 8a 5a [2] 8c 6f [2] a2 6f [2] 9d 73 }

  condition:
    any of them
}