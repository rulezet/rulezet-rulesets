rule TTP_XOR_WriteProcessMemory_ee19 {
  strings:
    $key_ee19 = { b9 6b [2] 8b 49 [2] 8d 7c [2] a3 7c [2] 9c 60 }

  condition:
    any of them
}