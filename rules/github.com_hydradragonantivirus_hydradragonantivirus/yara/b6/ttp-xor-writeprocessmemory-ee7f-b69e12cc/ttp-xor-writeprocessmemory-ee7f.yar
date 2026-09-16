rule TTP_XOR_WriteProcessMemory_ee7f {
  strings:
    $key_ee7f = { b9 0d [2] 8b 2f [2] 8d 1a [2] a3 1a [2] 9c 06 }

  condition:
    any of them
}