rule TTP_XOR_WriteProcessMemory_aef8 {
  strings:
    $key_aef8 = { f9 8a [2] cb a8 [2] cd 9d [2] e3 9d [2] dc 81 }

  condition:
    any of them
}