rule TTP_XOR_WriteProcessMemory_ee4c {
  strings:
    $key_ee4c = { b9 3e [2] 8b 1c [2] 8d 29 [2] a3 29 [2] 9c 35 }

  condition:
    any of them
}