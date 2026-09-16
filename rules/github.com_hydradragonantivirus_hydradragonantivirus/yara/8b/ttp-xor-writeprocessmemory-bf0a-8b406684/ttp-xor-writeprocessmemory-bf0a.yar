rule TTP_XOR_WriteProcessMemory_bf0a {
  strings:
    $key_bf0a = { e8 78 [2] da 5a [2] dc 6f [2] f2 6f [2] cd 73 }

  condition:
    any of them
}