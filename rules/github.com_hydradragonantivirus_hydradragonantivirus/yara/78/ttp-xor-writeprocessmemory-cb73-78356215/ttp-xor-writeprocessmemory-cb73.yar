rule TTP_XOR_WriteProcessMemory_cb73 {
  strings:
    $key_cb73 = { 9c 01 [2] ae 23 [2] a8 16 [2] 86 16 [2] b9 0a }

  condition:
    any of them
}