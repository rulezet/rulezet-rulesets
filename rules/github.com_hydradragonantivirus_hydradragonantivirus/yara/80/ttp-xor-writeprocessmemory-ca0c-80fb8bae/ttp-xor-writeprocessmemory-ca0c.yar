rule TTP_XOR_WriteProcessMemory_ca0c {
  strings:
    $key_ca0c = { 9d 7e [2] af 5c [2] a9 69 [2] 87 69 [2] b8 75 }

  condition:
    any of them
}