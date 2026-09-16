rule TTP_XOR_WriteProcessMemory_eb2f {
  strings:
    $key_eb2f = { bc 5d [2] 8e 7f [2] 88 4a [2] a6 4a [2] 99 56 }

  condition:
    any of them
}