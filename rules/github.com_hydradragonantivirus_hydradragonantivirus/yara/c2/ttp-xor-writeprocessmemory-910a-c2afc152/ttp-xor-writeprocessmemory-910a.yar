rule TTP_XOR_WriteProcessMemory_910a {
  strings:
    $key_910a = { c6 78 [2] f4 5a [2] f2 6f [2] dc 6f [2] e3 73 }

  condition:
    any of them
}