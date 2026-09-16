rule TTP_XOR_WriteProcessMemory_c139 {
  strings:
    $key_c139 = { 96 4b [2] a4 69 [2] a2 5c [2] 8c 5c [2] b3 40 }

  condition:
    any of them
}