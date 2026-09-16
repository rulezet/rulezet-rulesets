rule TTP_XOR_WriteProcessMemory_aee3 {
  strings:
    $key_aee3 = { f9 91 [2] cb b3 [2] cd 86 [2] e3 86 [2] dc 9a }

  condition:
    any of them
}