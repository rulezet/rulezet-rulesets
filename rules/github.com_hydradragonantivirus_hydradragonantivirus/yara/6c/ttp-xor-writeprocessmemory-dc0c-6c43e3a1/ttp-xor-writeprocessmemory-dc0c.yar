rule TTP_XOR_WriteProcessMemory_dc0c {
  strings:
    $key_dc0c = { 8b 7e [2] b9 5c [2] bf 69 [2] 91 69 [2] ae 75 }

  condition:
    any of them
}