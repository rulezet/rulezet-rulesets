rule TTP_XOR_WriteProcessMemory_f82c {
  strings:
    $key_f82c = { af 5e [2] 9d 7c [2] 9b 49 [2] b5 49 [2] 8a 55 }

  condition:
    any of them
}