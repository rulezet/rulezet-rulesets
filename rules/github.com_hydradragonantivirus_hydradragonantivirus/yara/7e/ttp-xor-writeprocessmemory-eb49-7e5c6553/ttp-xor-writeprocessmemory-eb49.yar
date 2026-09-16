rule TTP_XOR_WriteProcessMemory_eb49 {
  strings:
    $key_eb49 = { bc 3b [2] 8e 19 [2] 88 2c [2] a6 2c [2] 99 30 }

  condition:
    any of them
}