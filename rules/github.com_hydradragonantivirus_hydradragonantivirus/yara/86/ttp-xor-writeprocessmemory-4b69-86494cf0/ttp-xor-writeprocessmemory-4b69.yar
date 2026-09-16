rule TTP_XOR_WriteProcessMemory_4b69 {
  strings:
    $key_4b69 = { 1c 1b [2] 2e 39 [2] 28 0c [2] 06 0c [2] 39 10 }

  condition:
    any of them
}