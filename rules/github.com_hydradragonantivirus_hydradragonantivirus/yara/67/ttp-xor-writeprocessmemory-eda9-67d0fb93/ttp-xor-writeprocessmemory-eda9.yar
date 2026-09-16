rule TTP_XOR_WriteProcessMemory_eda9 {
  strings:
    $key_eda9 = { ba db [2] 88 f9 [2] 8e cc [2] a0 cc [2] 9f d0 }

  condition:
    any of them
}