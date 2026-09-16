rule TTP_XOR_WriteProcessMemory_ae75 {
  strings:
    $key_ae75 = { f9 07 [2] cb 25 [2] cd 10 [2] e3 10 [2] dc 0c }

  condition:
    any of them
}