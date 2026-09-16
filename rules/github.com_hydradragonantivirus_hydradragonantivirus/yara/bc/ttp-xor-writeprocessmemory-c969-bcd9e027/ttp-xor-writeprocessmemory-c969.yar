rule TTP_XOR_WriteProcessMemory_c969 {
  strings:
    $key_c969 = { 9e 1b [2] ac 39 [2] aa 0c [2] 84 0c [2] bb 10 }

  condition:
    any of them
}