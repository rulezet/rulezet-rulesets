rule TTP_XOR_WriteProcessMemory_c70c {
  strings:
    $key_c70c = { 90 7e [2] a2 5c [2] a4 69 [2] 8a 69 [2] b5 75 }

  condition:
    any of them
}