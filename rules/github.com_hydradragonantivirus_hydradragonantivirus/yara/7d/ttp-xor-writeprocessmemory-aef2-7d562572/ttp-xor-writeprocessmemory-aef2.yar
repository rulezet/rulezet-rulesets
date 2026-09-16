rule TTP_XOR_WriteProcessMemory_aef2 {
  strings:
    $key_aef2 = { f9 80 [2] cb a2 [2] cd 97 [2] e3 97 [2] dc 8b }

  condition:
    any of them
}