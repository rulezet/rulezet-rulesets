rule TTP_XOR_WriteProcessMemory_ee2c {
  strings:
    $key_ee2c = { b9 5e [2] 8b 7c [2] 8d 49 [2] a3 49 [2] 9c 55 }

  condition:
    any of them
}