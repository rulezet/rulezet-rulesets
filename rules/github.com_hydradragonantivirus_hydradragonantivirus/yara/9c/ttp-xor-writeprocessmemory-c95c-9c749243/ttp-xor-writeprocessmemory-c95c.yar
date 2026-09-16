rule TTP_XOR_WriteProcessMemory_c95c {
  strings:
    $key_c95c = { 9e 2e [2] ac 0c [2] aa 39 [2] 84 39 [2] bb 25 }

  condition:
    any of them
}