rule TTP_XOR_WriteProcessMemory_877a {
  strings:
    $key_877a = { d0 08 [2] e2 2a [2] e4 1f [2] ca 1f [2] f5 03 }

  condition:
    any of them
}