rule TTP_XOR_WriteProcessMemory_ee28 {
  strings:
    $key_ee28 = { b9 5a [2] 8b 78 [2] 8d 4d [2] a3 4d [2] 9c 51 }

  condition:
    any of them
}