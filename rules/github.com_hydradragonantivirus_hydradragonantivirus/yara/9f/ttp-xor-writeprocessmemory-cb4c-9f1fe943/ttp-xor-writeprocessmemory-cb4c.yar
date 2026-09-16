rule TTP_XOR_WriteProcessMemory_cb4c {
  strings:
    $key_cb4c = { 9c 3e [2] ae 1c [2] a8 29 [2] 86 29 [2] b9 35 }

  condition:
    any of them
}