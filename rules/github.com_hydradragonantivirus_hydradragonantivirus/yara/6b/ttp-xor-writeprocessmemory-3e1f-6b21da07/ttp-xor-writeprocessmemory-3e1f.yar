rule TTP_XOR_WriteProcessMemory_3e1f {
  strings:
    $key_3e1f = { 69 6d [2] 5b 4f [2] 5d 7a [2] 73 7a [2] 4c 66 }

  condition:
    any of them
}