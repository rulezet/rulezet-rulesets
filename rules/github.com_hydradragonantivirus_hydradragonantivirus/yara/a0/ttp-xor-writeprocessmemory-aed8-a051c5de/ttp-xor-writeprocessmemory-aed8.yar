rule TTP_XOR_WriteProcessMemory_aed8 {
  strings:
    $key_aed8 = { f9 aa [2] cb 88 [2] cd bd [2] e3 bd [2] dc a1 }

  condition:
    any of them
}