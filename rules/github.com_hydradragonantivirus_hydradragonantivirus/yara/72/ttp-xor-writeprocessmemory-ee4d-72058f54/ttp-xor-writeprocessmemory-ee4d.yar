rule TTP_XOR_WriteProcessMemory_ee4d {
  strings:
    $key_ee4d = { b9 3f [2] 8b 1d [2] 8d 28 [2] a3 28 [2] 9c 34 }

  condition:
    any of them
}