rule TTP_XOR_WriteProcessMemory_ee0a {
  strings:
    $key_ee0a = { b9 78 [2] 8b 5a [2] 8d 6f [2] a3 6f [2] 9c 73 }

  condition:
    any of them
}