rule TTP_XOR_WriteProcessMemory_3cea {
  strings:
    $key_3cea = { 6b 98 [2] 59 ba [2] 5f 8f [2] 71 8f [2] 4e 93 }

  condition:
    any of them
}