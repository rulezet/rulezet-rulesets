rule TTP_XOR_WriteProcessMemory_ad69 {
  strings:
    $key_ad69 = { fa 1b [2] c8 39 [2] ce 0c [2] e0 0c [2] df 10 }

  condition:
    any of them
}