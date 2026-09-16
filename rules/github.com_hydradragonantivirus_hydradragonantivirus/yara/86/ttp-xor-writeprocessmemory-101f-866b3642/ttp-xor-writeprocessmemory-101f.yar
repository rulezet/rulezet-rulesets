rule TTP_XOR_WriteProcessMemory_101f {
  strings:
    $key_101f = { 47 6d [2] 75 4f [2] 73 7a [2] 5d 7a [2] 62 66 }

  condition:
    any of them
}