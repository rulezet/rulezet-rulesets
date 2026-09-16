rule TTP_XOR_WriteProcessMemory_8011 {
  strings:
    $key_8011 = { d7 63 [2] e5 41 [2] e3 74 [2] cd 74 [2] f2 68 }

  condition:
    any of them
}