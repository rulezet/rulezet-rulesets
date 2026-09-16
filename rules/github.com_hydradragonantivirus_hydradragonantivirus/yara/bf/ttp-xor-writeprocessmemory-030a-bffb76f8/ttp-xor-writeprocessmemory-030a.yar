rule TTP_XOR_WriteProcessMemory_030a {
  strings:
    $key_030a = { 54 78 [2] 66 5a [2] 60 6f [2] 4e 6f [2] 71 73 }

  condition:
    any of them
}