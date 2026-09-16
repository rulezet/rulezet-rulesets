rule TTP_XOR_WriteProcessMemory_801a {
  strings:
    $key_801a = { d7 68 [2] e5 4a [2] e3 7f [2] cd 7f [2] f2 63 }

  condition:
    any of them
}