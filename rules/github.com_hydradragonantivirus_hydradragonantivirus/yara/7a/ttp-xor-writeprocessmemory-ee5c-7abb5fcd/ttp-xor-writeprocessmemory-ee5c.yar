rule TTP_XOR_WriteProcessMemory_ee5c {
  strings:
    $key_ee5c = { b9 2e [2] 8b 0c [2] 8d 39 [2] a3 39 [2] 9c 25 }

  condition:
    any of them
}