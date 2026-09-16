rule TTP_XOR_WriteProcessMemory_aec1 {
  strings:
    $key_aec1 = { f9 b3 [2] cb 91 [2] cd a4 [2] e3 a4 [2] dc b8 }

  condition:
    any of them
}