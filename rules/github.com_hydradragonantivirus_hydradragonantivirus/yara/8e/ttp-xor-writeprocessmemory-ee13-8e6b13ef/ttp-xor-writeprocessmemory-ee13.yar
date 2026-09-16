rule TTP_XOR_WriteProcessMemory_ee13 {
  strings:
    $key_ee13 = { b9 61 [2] 8b 43 [2] 8d 76 [2] a3 76 [2] 9c 6a }

  condition:
    any of them
}