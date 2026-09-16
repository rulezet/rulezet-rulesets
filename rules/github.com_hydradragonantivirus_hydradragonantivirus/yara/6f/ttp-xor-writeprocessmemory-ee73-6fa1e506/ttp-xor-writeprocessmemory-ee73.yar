rule TTP_XOR_WriteProcessMemory_ee73 {
  strings:
    $key_ee73 = { b9 01 [2] 8b 23 [2] 8d 16 [2] a3 16 [2] 9c 0a }

  condition:
    any of them
}