rule TTP_XOR_WriteProcessMemory_2669 {
  strings:
    $key_2669 = { 71 1b [2] 43 39 [2] 45 0c [2] 6b 0c [2] 54 10 }

  condition:
    any of them
}