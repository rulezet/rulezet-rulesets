rule TTP_XOR_WriteProcessMemory_ca69 {
  strings:
    $key_ca69 = { 9d 1b [2] af 39 [2] a9 0c [2] 87 0c [2] b8 10 }

  condition:
    any of them
}