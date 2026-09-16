rule TTP_XOR_WriteProcessMemory_091f {
  strings:
    $key_091f = { 5e 6d [2] 6c 4f [2] 6a 7a [2] 44 7a [2] 7b 66 }

  condition:
    any of them
}