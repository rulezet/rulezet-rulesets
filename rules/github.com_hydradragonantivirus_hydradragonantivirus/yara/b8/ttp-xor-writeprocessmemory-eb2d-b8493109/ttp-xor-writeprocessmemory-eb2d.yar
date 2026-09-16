rule TTP_XOR_WriteProcessMemory_eb2d {
  strings:
    $key_eb2d = { bc 5f [2] 8e 7d [2] 88 48 [2] a6 48 [2] 99 54 }

  condition:
    any of them
}