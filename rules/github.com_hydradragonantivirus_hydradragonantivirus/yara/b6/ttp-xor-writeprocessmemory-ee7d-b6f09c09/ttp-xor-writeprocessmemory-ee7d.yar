rule TTP_XOR_WriteProcessMemory_ee7d {
  strings:
    $key_ee7d = { b9 0f [2] 8b 2d [2] 8d 18 [2] a3 18 [2] 9c 04 }

  condition:
    any of them
}