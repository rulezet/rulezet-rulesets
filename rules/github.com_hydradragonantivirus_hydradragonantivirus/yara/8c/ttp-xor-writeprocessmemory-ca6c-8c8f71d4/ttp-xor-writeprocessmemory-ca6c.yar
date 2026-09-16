rule TTP_XOR_WriteProcessMemory_ca6c {
  strings:
    $key_ca6c = { 9d 1e [2] af 3c [2] a9 09 [2] 87 09 [2] b8 15 }

  condition:
    any of them
}