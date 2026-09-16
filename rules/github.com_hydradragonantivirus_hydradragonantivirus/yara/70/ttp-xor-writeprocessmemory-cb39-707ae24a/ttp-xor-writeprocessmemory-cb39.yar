rule TTP_XOR_WriteProcessMemory_cb39 {
  strings:
    $key_cb39 = { 9c 4b [2] ae 69 [2] a8 5c [2] 86 5c [2] b9 40 }

  condition:
    any of them
}