rule TTP_XOR_WriteProcessMemory_421f {
  strings:
    $key_421f = { 15 6d [2] 27 4f [2] 21 7a [2] 0f 7a [2] 30 66 }

  condition:
    any of them
}