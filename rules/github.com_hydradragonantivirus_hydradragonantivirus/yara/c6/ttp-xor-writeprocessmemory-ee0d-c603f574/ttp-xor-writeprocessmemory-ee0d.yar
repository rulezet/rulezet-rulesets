rule TTP_XOR_WriteProcessMemory_ee0d {
  strings:
    $key_ee0d = { b9 7f [2] 8b 5d [2] 8d 68 [2] a3 68 [2] 9c 74 }

  condition:
    any of them
}