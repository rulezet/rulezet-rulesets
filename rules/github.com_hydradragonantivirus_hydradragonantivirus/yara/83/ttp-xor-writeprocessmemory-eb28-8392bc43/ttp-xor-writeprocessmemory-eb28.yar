rule TTP_XOR_WriteProcessMemory_eb28 {
  strings:
    $key_eb28 = { bc 5a [2] 8e 78 [2] 88 4d [2] a6 4d [2] 99 51 }

  condition:
    any of them
}