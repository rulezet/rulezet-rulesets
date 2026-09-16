rule TTP_XOR_WriteProcessMemory_28cd {
  strings:
    $key_28cd = { 7f bf [2] 4d 9d [2] 4b a8 [2] 65 a8 [2] 5a b4 }

  condition:
    any of them
}